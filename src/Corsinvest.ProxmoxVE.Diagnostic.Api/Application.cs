/*
 * SPDX-FileCopyrightText: Copyright Corsinvest Srl
 * SPDX-License-Identifier: GPL-3.0-only
 */

using Corsinvest.ProxmoxVE.Api;
using Corsinvest.ProxmoxVE.Api.Extension;
using Corsinvest.ProxmoxVE.Api.Shared.Models.Cluster;
using Corsinvest.ProxmoxVE.Api.Shared.Models.Common;
using Corsinvest.ProxmoxVE.Api.Shared.Models.Node;
using Corsinvest.ProxmoxVE.Api.Shared.Models.Vm;
using Corsinvest.ProxmoxVE.Api.Shared.Utils;

namespace Corsinvest.ProxmoxVE.Diagnostic.Api;

/// <summary>
/// Diagnostic helper
/// </summary>
public class Application
{
    /// <summary>
    /// Analyze cluster by querying PVE API directly
    /// </summary>
    public static async Task<ICollection<DiagnosticResult>> AnalyzeAsync(PveClient client,
                                                                         Settings settings,
                                                                         List<DiagnosticResult> ignoredIssues)
    {
        var result = new List<DiagnosticResult>();
        var now = DateTime.Now;

        var allResources = await client.Cluster.Resources.GetAsync();
        var resources = allResources.Where(a => !a.IsUnknown).ToList();

        // Unknown resources
        result.AddRange(allResources.Where(a => a.IsUnknown)
                                    .Select(a => new DiagnosticResult
                                    {
                                        Id = a.GetWebUrl(),
                                        ErrorCode = "CU0001",
                                        Description = $"Unknown resource {a.Type}",
                                        Context = DiagnosticResult.DecodeContext(a.Type),
                                        SubContext = "Status",
                                        Gravity = DiagnosticResultGravity.Critical,
                                    }));

        var clusterConfigNodes = await client.Cluster.Config.Nodes.GetAsync();
        var clusterBackups = await client.Cluster.Backup.GetAsync();

        await CheckStorageAsync(client, result, resources, settings, now);
        await CheckNodesAsync(client, result, resources, settings, clusterConfigNodes.Any(), now);
        await CheckQemuAsync(client, result, resources, settings, clusterBackups, now);
        await CheckLxcAsync(client, result, resources, settings, clusterBackups, now);

        foreach (var ignoredIssue in ignoredIssues)
        {
            foreach (var item in result.Where(a => ignoredIssue.CheckIgnoreIssue(a)))
            {
                item.IsIgnoredIssue = true;
            }
        }

        return result;
    }

    private record StorageContent(string Id,
                                  string Volume,
                                  string Storage,
                                  long VmId,
                                  string FileName,
                                  long Size);

    private static async Task CheckStorageAsync(PveClient client,
                                                List<DiagnosticResult> result,
                                                List<ClusterResource> resources,
                                                Settings settings,
                                                DateTime now)
    {
        // storage not available
        result.AddRange(resources.Where(a => a.ResourceType == ClusterResourceType.Storage && !a.IsAvailable)
                                 .Select(a => new DiagnosticResult
                                 {
                                     Id = a.GetWebUrl(),
                                     ErrorCode = "CS0001",
                                     Description = "Storage not available",
                                     Context = DiagnosticResultContext.Storage,
                                     SubContext = "Status",
                                     Gravity = DiagnosticResultGravity.Critical,
                                 }));

        // storage usage
        CheckThreshold(result,
                       settings.Storage.Threshold,
                       "CS0001",
                       DiagnosticResultContext.Storage,
                       "Usage",
                       resources.Where(a => a.ResourceType == ClusterResourceType.Storage && a.IsAvailable)
                                .Select(a => new ThresholdDataPoint(Convert.ToDouble(a.DiskUsage),
                                                                    Convert.ToDouble(a.DiskSize),
                                                                    a.GetWebUrl(),
                                                                    "Storage")),
                       false,
                       true);

        #region Orphaned Images
        var storagesImages = new List<StorageContent>();
        foreach (var item in resources.Where(a => a.ResourceType == ClusterResourceType.Storage
                                                  && a.Content != null
                                                  && a.Content.Split(",").Contains("images")))
        {
            var nodeApi = client.Nodes[item.Node];
            var nodeStorages = await nodeApi.Storage.GetAsync();
            foreach (var ns in nodeStorages.Where(a => a.Storage == item.Storage
                                                       && a.Content != null
                                                       && a.Content.Split(",").Contains("images")
                                                       && a.Active))
            {
                var content = await nodeApi.Storage[ns.Storage].Content.GetAsync();
                storagesImages.AddRange([.. content.Where(a => a.Content == "images")
                                                   .Select(a => new StorageContent(item.GetWebUrl(),
                                                                                   a.Volume,
                                                                                   ns.Storage,
                                                                                   a.VmId,
                                                                                   a.FileName,
                                                                                   a.Size))]);
            }
        }

        // deduplicate
        storagesImages = [.. storagesImages.DistinctBy(a => a.Volume)];

        foreach (var item in resources.Where(a => a.ResourceType == ClusterResourceType.Vm))
        {
            var nodeApi = client.Nodes[item.Node];
            VmConfig config = item.VmType == VmType.Qemu
                                ? await nodeApi.Qemu[item.VmId].Config.GetAsync()
                                : await nodeApi.Lxc[item.VmId].Config.GetAsync();

            foreach (var disk in config.Disks)
            {
                storagesImages.RemoveAll(a => a.VmId == item.VmId
                                              && a.Storage == disk.Storage
                                              && a.FileName == disk.FileName);
            }
        }

        result.AddRange(storagesImages.Select(a => new DiagnosticResult
        {
            Id = a.Id,
            ErrorCode = "WN0001",
            Description = $"Image Orphaned {FormatHelper.FromBytes(a.Size)} file {a.FileName}",
            Context = DiagnosticResultContext.Storage,
            SubContext = "Image",
            Gravity = DiagnosticResultGravity.Warning,
        }));
        #endregion
    }

    private record NodeCompareData(NodeVersion Version,
                                   string[] Hosts,
                                   NodeDns Dns,
                                   string Timezone,
                                   IEnumerable<NodeAptVersion> AptVersions);

    private static async Task CheckNodesAsync(PveClient client,
                                              List<DiagnosticResult> result,
                                              List<ClusterResource> resources,
                                              Settings settings,
                                              bool hasCluster,
                                              DateTime now)
    {
        var endOfLife = new Dictionary<int, DateTime>
        {
            { 7, new DateTime(2024, 07, 01) },
            { 6, new DateTime(2022, 09, 01) },
            { 5, new DateTime(2020, 07, 01) },
            { 4, new DateTime(2018, 06, 01) },
        };

        var onlineNodes = resources.Where(a => a.ResourceType == ClusterResourceType.Node && a.IsOnline).ToList();

        // collect lightweight data for cross-node comparisons
        var nodeCompareData = new Dictionary<string, NodeCompareData>();
        foreach (var item in onlineNodes)
        {
            var api = client.Nodes[item.Node];
            nodeCompareData[item.Node] = new NodeCompareData(await api.Version.GetAsync(),
                                                             ((string)(await api.Hosts.GetEtcHosts()).ToData().data).Split('\n'),
                                                             await api.Dns.GetAsync(),
                                                             (await api.Time.Time()).ToData().timezone as string ?? string.Empty,
                                                             await api.Apt.Versions.GetAsync());
        }

        foreach (var item in resources.Where(a => a.ResourceType == ClusterResourceType.Node))
        {
            var id = item.GetWebUrl();

            if (!item.IsOnline)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WN0001",
                    Description = "Node not online",
                    Context = DiagnosticResultContext.Node,
                    SubContext = "Status",
                    Gravity = DiagnosticResultGravity.Warning,
                });
                continue;
            }

            var nodeApi = client.Nodes[item.Node];
            var (version, hosts, dns, timezone, aptVersions) = nodeCompareData[item.Node];
            if (!int.TryParse(version.Version?.Split(".")[0], out var nodeVersion)) { continue; }

            #region End Of Life
            if (endOfLife.TryGetValue(nodeVersion, out var eolDate) && now.Date >= eolDate)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WN0001",
                    Description = $"Version {version.Version} end of life {eolDate}",
                    Context = DiagnosticResultContext.Node,
                    SubContext = "EOL",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
            #endregion

            #region Subscription
            var subscription = await nodeApi.Subscription.GetAsync();
            if (!subscription.Status.Equals("active", StringComparison.CurrentCultureIgnoreCase))
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WN0001",
                    Description = "Node not have subscription active",
                    Context = DiagnosticResultContext.Node,
                    SubContext = "Subscription",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
            #endregion

            #region RrdData
            var rrdData = settings.Node.TimeSeries switch
            {
                SettingsTimeSeriesType.Day => await nodeApi.Rrddata.GetAsync(RrdDataTimeFrame.Day, RrdDataConsolidation.Average),
                SettingsTimeSeriesType.Week => await nodeApi.Rrddata.GetAsync(RrdDataTimeFrame.Week, RrdDataConsolidation.Average),
                _ => throw new ArgumentOutOfRangeException("settings.Node.TimeSeries"),
            };

            CheckNodeRrd(result, settings, id, rrdData);
            #endregion

            #region Cross-node comparisons
            var checkInNodes = new bool[] { true, true, true, true };
            foreach (var other in onlineNodes.Where(a => a.Node != item.Node))
            {
                if (!nodeCompareData.TryGetValue(other.Node, out var otherData)) { continue; }
                var (otherVersion, otherHosts, otherDns, otherTimezone, otherAptVersions) = otherData;

                if (checkInNodes[0] && !version.IsEqual(otherVersion))
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WN0001",
                        Description = "Nodes version not equal",
                        Context = DiagnosticResultContext.Node,
                        SubContext = "Version",
                        Gravity = DiagnosticResultGravity.Critical,
                    });
                    checkInNodes[0] = false;
                }

                if (checkInNodes[1] && string.Join("", hosts) != string.Join("", otherHosts))
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WN0001",
                        Description = "Nodes hosts configuration not equal",
                        Context = DiagnosticResultContext.Node,
                        SubContext = "Hosts",
                        Gravity = DiagnosticResultGravity.Warning,
                    });
                    checkInNodes[1] = false;
                }

                if (checkInNodes[2] && !dns.IsEqual(otherDns))
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WN0001",
                        Description = "Nodes DNS not equal",
                        Context = DiagnosticResultContext.Node,
                        SubContext = "DNS",
                        Gravity = DiagnosticResultGravity.Warning,
                    });
                    checkInNodes[2] = false;
                }

                if (checkInNodes[3] && timezone != otherTimezone)
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WN0001",
                        Description = "Nodes Timezone not equal",
                        Context = DiagnosticResultContext.Node,
                        SubContext = "Timezone",
                        Gravity = DiagnosticResultGravity.Warning,
                    });
                    checkInNodes[3] = false;
                }
            }
            #endregion

            #region Network Card
            result.AddRange((await nodeApi.Network.GetAsync())
                            .Where(a => a.Type == "eth" && !a.Active)
                            .Select(a => new DiagnosticResult
                            {
                                Id = id,
                                ErrorCode = "WN0002",
                                Description = $"Network card '{a.Interface}' not active",
                                Context = DiagnosticResultContext.Node,
                                SubContext = "Network",
                                Gravity = DiagnosticResultGravity.Warning,
                            }));
            #endregion

            #region Package Versions
            var addErrPackageVersions = false;
            foreach (var other in onlineNodes.Where(a => a.Node != item.Node))
            {
                if (addErrPackageVersions) { break; }
                if (!nodeCompareData.TryGetValue(other.Node, out var otherPkgData)) { continue; }
                var (_, _, _, _, otherAptVersions) = otherPkgData;
                foreach (var pkg in aptVersions)
                {
                    if (!otherAptVersions.Any(a => a.Version == pkg.Version && a.Title == pkg.Title && a.Package == pkg.Package))
                    {
                        addErrPackageVersions = true;
                        result.Add(new DiagnosticResult
                        {
                            Id = id,
                            ErrorCode = "WN0001",
                            Description = "Nodes package version not equal",
                            Context = DiagnosticResultContext.Node,
                            SubContext = "PackageVersions",
                            Gravity = DiagnosticResultGravity.Critical,
                        });
                        break;
                    }
                }
            }
            #endregion

            #region Services
            var serviceExcluded = new List<string>();
            if (!hasCluster) { serviceExcluded.Add("corosync"); }
            serviceExcluded.Add(nodeVersion >= 7
                                    ? "systemd-timesyncd"
                                    : "chrony");

            result.AddRange((await nodeApi.Services.GetAsync())
                            .Where(a => !a.IsRunning && !serviceExcluded.Contains(a.Name))
                            .Select(a => new DiagnosticResult
                            {
                                Id = id,
                                ErrorCode = "WN0002",
                                Description = $"Service '{a.Description}' not running",
                                Context = DiagnosticResultContext.Node,
                                SubContext = "Service",
                                Gravity = DiagnosticResultGravity.Warning,
                            }));
            #endregion

            #region Certificates
            result.AddRange((await nodeApi.Certificates.Info.GetAsync())
                              .Where(a => DateTimeOffset.FromUnixTimeSeconds(a.NotAfter) < now)
                              .Select(a => new DiagnosticResult
                              {
                                  Id = id,
                                  ErrorCode = "WN0002",
                                  Description = $"Certificate '{a.FileName}' expired",
                                  Context = DiagnosticResultContext.Node,
                                  SubContext = "Certificates",
                                  Gravity = DiagnosticResultGravity.Critical,
                              }));
            #endregion

            #region Replication
            var replCount = (await nodeApi.Replication.GetAsync())
                                .Count(a => a.ExtensionData != null && a.ExtensionData.ContainsKey("errors"));
            if (replCount > 0)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "IN0001",
                    Description = $"{replCount} Replication has errors",
                    Context = DiagnosticResultContext.Node,
                    SubContext = "Replication",
                    Gravity = DiagnosticResultGravity.Critical,
                });
            }
            #endregion

            await CheckNodeDiskAsync(nodeApi, result, settings, id);

            #region APT Updates
            var aptUpdate = await nodeApi.Apt.Update.GetAsync();
            var updateCount = aptUpdate.Count();
            if (updateCount > 0)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "IN0001",
                    Description = $"{updateCount} Update available",
                    Context = DiagnosticResultContext.Node,
                    SubContext = "Update",
                    Gravity = DiagnosticResultGravity.Info,
                });
            }

            var updateImportantCount = aptUpdate.Count(a => a.Priority == "important");
            if (updateImportantCount > 0)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "IN0001",
                    Description = $"{updateImportantCount} Update Important available",
                    Context = DiagnosticResultContext.Node,
                    SubContext = "Update",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
            #endregion

            #region Task history
            var dayTask = new DateTimeOffset(now.AddDays(-2)).ToUnixTimeSeconds();
            var tasks = (await nodeApi.Tasks.GetAsync(errors: true, limit: 1000)).Where(a => a.StartTime >= dayTask);
            CheckTaskHistory(result, tasks, DiagnosticResultContext.Node, id);
            #endregion
        }
    }

    private static async Task CheckNodeDiskAsync(PveClient.PveNodes.PveNodeItem nodeApi,
                                                 List<DiagnosticResult> result,
                                                 Settings settings,
                                                 string id)
    {
        #region Disks
        var disksAll = await nodeApi.Disks.List.GetAsync(include_partitions: false);

        result.AddRange(disksAll.Where(a => a.Health != "PASSED" && a.Health != "OK")
                                .Select(a => new DiagnosticResult
                                {
                                    Id = id,
                                    ErrorCode = "CN0003",
                                    Description = $"Disk '{a.DevPath}' S.M.A.R.T. status problem",
                                    Context = DiagnosticResultContext.Node,
                                    SubContext = "S.M.A.R.T.",
                                    Gravity = DiagnosticResultGravity.Warning,
                                }));

        result.AddRange(disksAll.Where(a => a.IsSsd && a.Wearout == "N/A")
                                .Select(a => new DiagnosticResult
                                {
                                    Id = id,
                                    ErrorCode = "CN0003",
                                    Description = $"Disk ssd '{a.DevPath}' wearout not valid.",
                                    Context = DiagnosticResultContext.Node,
                                    SubContext = "SSD Wearout",
                                    Gravity = DiagnosticResultGravity.Warning,
                                }));

        CheckThreshold(result,
                       settings.SsdWearoutThreshold,
                       "CN0003",
                       DiagnosticResultContext.Node,
                       "SSD Wearout",
                       disksAll.Where(a => a.IsSsd && a.Wearout != "N/A")
                               .Select(a => new ThresholdDataPoint(100.0 - Convert.ToDouble(a.Wearout), 0d, id, $"SSD '{a.DevPath}'")),
                       true,
                       false);
        #endregion

        #region Zfs
        var zfsList = await nodeApi.Disks.Zfs.GetAsync() ?? [];

        result.AddRange(zfsList.Where(a => a.Health != "ONLINE")
                               .Select(a => new DiagnosticResult
                               {
                                   Id = id,
                                   ErrorCode = "CN0003",
                                   Description = $"Zfs '{a.Name}' health problem {a.Health}",
                                   Context = DiagnosticResultContext.Node,
                                   SubContext = "Zfs",
                                   Gravity = DiagnosticResultGravity.Critical,
                               }));

        CheckThreshold(result,
                       settings.Storage.Threshold,
                       "CS0001",
                       DiagnosticResultContext.Storage,
                       "Zfs",
                       zfsList.Select(a => new ThresholdDataPoint(Convert.ToDouble(a.Alloc),
                                                                  Convert.ToDouble(a.Size),
                                                                  $"{id} ({a.Name})",
                                                                  $"Zfs '{a.Name}'")),
                       false,
                       true);
        #endregion
    }

    private static async Task CheckQemuAsync(PveClient client,
                                             List<DiagnosticResult> result,
                                             List<ClusterResource> resources,
                                             Settings settings,
                                             IEnumerable<ClusterBackup> clusterBackups,
                                             DateTime now)
    {
        var osNotMaintained = new[] { "win10", "win8", "win7", "w2k8", "wxp", "w2k" };

        foreach (var item in resources.Where(a => a.ResourceType == ClusterResourceType.Vm
                                                  && a.VmType == VmType.Qemu
                                                  && !a.IsTemplate))
        {
            var nodeApi = client.Nodes[item.Node];
            var vmApi = nodeApi.Qemu[item.VmId];
            var id = item.GetWebUrl();
            var config = await vmApi.Config.GetAsync();

            #region OS
            if (config.OsType == null)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = "OsType not set!",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "OS",
                    Gravity = DiagnosticResultGravity.Critical,
                });
            }
            else if (osNotMaintained.Contains(config.OsType))
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = $"OS '{config.OsTypeDecode}' not maintained from vendor!",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "OSNotMaintained",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
            #endregion

            #region Agent
            if (!config.AgentEnabled)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = "Qemu Agent not enabled",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "Agent",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
            else if (item.IsRunning)
            {
                try
                {
                    var agentHost = await vmApi.Agent.GetHostName.GetAsync();
                    if (string.IsNullOrWhiteSpace(agentHost?.Result?.HostName))
                    {
                        result.Add(new DiagnosticResult
                        {
                            Id = id,
                            ErrorCode = "WV0001",
                            Description = "Qemu Agent in guest not running",
                            Context = DiagnosticResultContext.Qemu,
                            SubContext = "Agent",
                            Gravity = DiagnosticResultGravity.Warning,
                        });
                    }
                }
                catch
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WV0001",
                        Description = "Qemu Agent in guest not running",
                        Context = DiagnosticResultContext.Qemu,
                        SubContext = "Agent",
                        Gravity = DiagnosticResultGravity.Warning,
                    });
                }
            }
            #endregion

            if (!config.OnBoot)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = "Start on boot not enabled",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "StartOnBoot",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }

            if (!config.Protection)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = "For production environment is better VM Protection = enabled",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "Protection",
                    Gravity = DiagnosticResultGravity.Info,
                });
            }

            if (config.IsLocked)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = $"VM is locked by '{config.Lock}'",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "Status",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }

            #region Virtio
            if (config.ExtensionData.TryGetValue("scsihw", out var scsiHw) && !scsiHw.ToString()!.StartsWith("virtio"))
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "WV0001",
                    Description = "For more performance switch controller to VirtIO SCSI",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "VirtIO",
                    Gravity = DiagnosticResultGravity.Info,
                });
                result.AddRange(config.Disks.Where(a => !a.Id.StartsWith("virtio"))
                                            .Select(a => new DiagnosticResult
                                            {
                                                Id = id,
                                                ErrorCode = "WV0001",
                                                Description = $"For more performance switch '{a.Id}' hdd to VirtIO",
                                                Context = DiagnosticResultContext.Qemu,
                                                SubContext = "VirtIO",
                                                Gravity = DiagnosticResultGravity.Info,
                                            }));
            }

            for (int i = 0; i < 256; i++)
            {
                var netId = $"net{i}";
                if (config.ExtensionData.TryGetValue(netId, out var netValue) && !(netValue + "").StartsWith("virtio"))
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WV0001",
                        Description = $"For more performance switch '{netId}' network to VirtIO",
                        Context = DiagnosticResultContext.Qemu,
                        SubContext = "VirtIO",
                        Gravity = DiagnosticResultGravity.Info,
                    });
                }
            }
            #endregion

            #region Unused disk
            var nodeStorages = await nodeApi.Storage.GetAsync();
            foreach (var unused in config.ExtensionData.Keys.Where(a => a.StartsWith("unused")))
            {
                var volume = config.ExtensionData[unused].ToString()!;
                var volumeParts = volume.Split(":");
                if (volumeParts.Length < 2) { continue; }
                var storageName = volumeParts[0];
                var ns = nodeStorages.FirstOrDefault(a => a.Storage == storageName);
                var size = string.Empty;
                if (ns != null && ns.Active)
                {
                    var contents = await nodeApi.Storage[ns.Storage].Content.GetAsync();
                    size = FormatHelper.FromBytes(contents.FirstOrDefault(a => a.Volume == volume)?.Size ?? 0).ToString();
                }
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "IV0001",
                    Description = $"disk '{unused}' {size} ",
                    Context = DiagnosticResultContext.Qemu,
                    SubContext = "Hardware",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
            #endregion

            #region Cdrom
            foreach (var value in config.ExtensionData.Values.Where(a => a != null).Select(a => a.ToString()!))
            {
                if (value.Contains("media=cdrom") && value != "none,media=cdrom")
                {
                    result.Add(new DiagnosticResult
                    {
                        Id = id,
                        ErrorCode = "WV0002",
                        Description = "Cdrom mounted",
                        Context = DiagnosticResultContext.Qemu,
                        SubContext = "Hardware",
                        Gravity = DiagnosticResultGravity.Warning,
                    });
                }
            }
            #endregion

            var rrdData = settings.Qemu.TimeSeries switch
            {
                SettingsTimeSeriesType.Day => await vmApi.Rrddata.GetAsync(RrdDataTimeFrame.Day, RrdDataConsolidation.Average),
                SettingsTimeSeriesType.Week => await vmApi.Rrddata.GetAsync(RrdDataTimeFrame.Week, RrdDataConsolidation.Average),
                _ => throw new NotImplementedException("settings.Qemu.TimeSeries"),
            };

            await CheckCommonVmAsync(client,
                                     result,
                                     settings.Qemu,
                                     config,
                                     await vmApi.Pending.GetAsync(),
                                     await vmApi.Snapshot.GetAsync(),
                                     rrdData,
                                     DiagnosticResultContext.Qemu,
                                     item.Node,
                                     item.VmId,
                                     id,
                                     clusterBackups,
                                     now);
        }
    }

    private static async Task CheckLxcAsync(PveClient client,
                                            List<DiagnosticResult> result,
                                            List<ClusterResource> resources,
                                            Settings settings,
                                            IEnumerable<ClusterBackup> clusterBackups,
                                            DateTime now)
    {
        foreach (var item in resources.Where(a => a.ResourceType == ClusterResourceType.Vm
                                                  && a.VmType == VmType.Lxc
                                                  && !a.IsTemplate))
        {
            var vmApi = client.Nodes[item.Node].Lxc[item.VmId];
            var id = item.GetWebUrl();

            var rrdData = settings.Lxc.TimeSeries switch
            {
                SettingsTimeSeriesType.Day => await vmApi.Rrddata.GetAsync(RrdDataTimeFrame.Day, RrdDataConsolidation.Average),
                SettingsTimeSeriesType.Week => await vmApi.Rrddata.GetAsync(RrdDataTimeFrame.Week, RrdDataConsolidation.Average),
                _ => throw new NotImplementedException("settings.Lxc.TimeSeries"),
            };

            await CheckCommonVmAsync(client,
                                     result,
                                     settings.Lxc,
                                     await vmApi.Config.GetAsync(),
                                     await vmApi.Pending.GetAsync(),
                                     await vmApi.Snapshot.GetAsync(),
                                     rrdData,
                                     DiagnosticResultContext.Lxc,
                                     item.Node,
                                     item.VmId,
                                     id,
                                     clusterBackups,
                                     now);
        }
    }

    private static async Task CheckCommonVmAsync(PveClient client,
                                                 List<DiagnosticResult> result,
                                                 SettingsThresholdHost thresholdHost,
                                                 VmConfig config,
                                                 IEnumerable<KeyValue> pending,
                                                 IEnumerable<VmSnapshot> snapshots,
                                                 IEnumerable<VmRrdData> rrdData,
                                                 DiagnosticResultContext context,
                                                 string node,
                                                 long vmId,
                                                 string id,
                                                 IEnumerable<ClusterBackup> clusterBackups,
                                                 DateTime now)
    {
        #region VM State
        result.AddRange(pending.Where(a => a.Key == "vmstate")
                               .Select(a => new DiagnosticResult
                               {
                                   Id = id,
                                   ErrorCode = "WV0001",
                                   Description = $"Found vmstate '{a.Value}'",
                                   Context = context,
                                   SubContext = "VM State",
                                   Gravity = DiagnosticResultGravity.Critical,
                               }));
        #endregion

        #region Backup config
        var foundBackupConfig = clusterBackups.Any(a => a.Enabled && a.All);
        if (!foundBackupConfig)
        {
            foundBackupConfig = clusterBackups.Where(a => a.Enabled && !string.IsNullOrEmpty(a.VmId))
                                              .SelectMany(a => a.VmId.Split(","))
                                              .Any(a => long.TryParse(a.Trim(), out var id) && id == vmId);
            if (!foundBackupConfig)
            {
                foreach (var poolId in clusterBackups.Where(a => a.Enabled && !string.IsNullOrWhiteSpace(a.Pool)).Select(a => a.Pool))
                {
                    var poolDetail = await client.Pools[poolId].GetAsync();
                    foundBackupConfig = poolDetail.Members.Any(a => a.ResourceType == ClusterResourceType.Vm && a.VmId == vmId);
                    if (foundBackupConfig) { break; }
                }
            }

            if (!foundBackupConfig)
            {
                result.Add(new DiagnosticResult
                {
                    Id = id,
                    ErrorCode = "CC0001",
                    Description = "vzdump backup not configured",
                    Context = context,
                    SubContext = "Backup",
                    Gravity = DiagnosticResultGravity.Warning,
                });
            }
        }

        result.AddRange(config.Disks.Where(a => !a.Backup)
                                    .Select(a => new DiagnosticResult
                                    {
                                        Id = id,
                                        ErrorCode = "WV0001",
                                        Description = $"Disk '{a.Id}' disabled for backup",
                                        Context = context,
                                        SubContext = "Backup",
                                        Gravity = DiagnosticResultGravity.Critical,
                                    }));

        // check backup age via storage content
        var nodeApi = client.Nodes[node];
        var nodeStorages = await nodeApi.Storage.GetAsync();
        var backupContents = new List<NodeStorageContent>();
        foreach (var ns in nodeStorages.Where(a => a.Content != null && a.Content.Split(",").Contains("backup") && a.Active))
        {
            var contents = await nodeApi.Storage[ns.Storage].Content.GetAsync();
            backupContents.AddRange(contents.Where(a => a.VmId == vmId && a.Content == "backup"));
        }

        const int dayOld = 60;
        const int dayRecent = 7;
        var oldBackups = backupContents.Where(a => a.CreationDate.Date <= now.Date.AddDays(-dayOld)).ToList();
        if (oldBackups.Count > 0)
        {
            result.Add(new DiagnosticResult
            {
                Id = id,
                ErrorCode = "CC0001",
                Description = $"{oldBackups.Count} backup {FormatHelper.FromBytes(oldBackups.Sum(a => a.Size))} more {dayOld} days are found!",
                Context = context,
                SubContext = "Backup",
                Gravity = DiagnosticResultGravity.Warning,
            });
        }

        if (!backupContents.Any(a => a.CreationDate.Date >= now.Date.AddDays(-dayRecent)))
        {
            result.Add(new DiagnosticResult
            {
                Id = id,
                ErrorCode = "CC0001",
                Description = "No recent backups found!",
                Context = context,
                SubContext = "Backup",
                Gravity = DiagnosticResultGravity.Warning,
            });
        }
        #endregion

        #region Task history
        var dayTask = new DateTimeOffset(now.AddDays(-2)).ToUnixTimeSeconds();
        var tasks = (await nodeApi.Tasks.GetAsync(errors: true, limit: 1000))
                    .Where(a => a.StartTime >= dayTask && (a.VmId?.Equals(vmId.ToString()) ?? false));
        CheckTaskHistory(result, tasks, context, id);
        #endregion

        CheckSnapshots(result, snapshots, now, id, context);

        CheckThresholdHost(result, thresholdHost, context, id, rrdData.Select(a => new ThresholdRddData(a, a, a)));
    }

    private static void CheckTaskHistory(List<DiagnosticResult> result,
                                         IEnumerable<NodeTask> tasks,
                                         DiagnosticResultContext context,
                                         string id)
    {
        var tasksCount = tasks.Count(a => !a.StatusOk);
        if (tasksCount > 0)
        {
            result.Add(new DiagnosticResult
            {
                Id = id,
                ErrorCode = "IN0001",
                Description = $"{tasksCount} Task history has errors",
                Context = context,
                SubContext = "Tasks",
                Gravity = DiagnosticResultGravity.Critical,
            });
        }
    }

    private static void CheckSnapshots(List<DiagnosticResult> result,
                                       IEnumerable<VmSnapshot> snapshots,
                                       DateTime execution,
                                       string id,
                                       DiagnosticResultContext context)
    {
        const string autosnapAppName = "cv4pve-autosnap";
        const string autosnapAppNameOld = "eve4pve-autosnap";

        if (!snapshots.Any(a => a.Description == autosnapAppName || a.Description == $"{autosnapAppName}\n"))
        {
            result.Add(new DiagnosticResult
            {
                Id = id,
                ErrorCode = "WV0003",
                Description = $"'{autosnapAppName}' not configured",
                Context = context,
                SubContext = "AutoSnapshot",
                Gravity = DiagnosticResultGravity.Warning,
            });
        }

        if (snapshots.Any(a => a.Description == autosnapAppNameOld || a.Description == $"{autosnapAppNameOld}\n"))
        {
            result.Add(new DiagnosticResult
            {
                Id = id,
                ErrorCode = "WV0003",
                Description = $"Old AutoSnap '{autosnapAppNameOld}' are present. Update new version",
                Context = context,
                SubContext = "AutoSnapshot",
                Gravity = DiagnosticResultGravity.Warning,
            });
        }

        var snapOldCount = snapshots.Count(a => a.Name != "current" && a.Date < execution.AddMonths(-1));
        if (snapOldCount > 0)
        {
            result.Add(new DiagnosticResult
            {
                Id = id,
                ErrorCode = "WV0003",
                Description = $"{snapOldCount} snapshots older than 1 month",
                Context = context,
                SubContext = "SnapshotOld",
                Gravity = DiagnosticResultGravity.Warning,
            });
        }
    }

    private record ThresholdRddData(IMemory Memory, INetIO NetIO, ICpu Cpu);

    private static void CheckThresholdHost(List<DiagnosticResult> result,
                                           SettingsThresholdHost thresholdHost,
                                           DiagnosticResultContext context,
                                           string id,
                                           IEnumerable<ThresholdRddData> rrdData)
    {
        CheckThreshold(result,
                       thresholdHost.Cpu,
                       "WV0002",
                       context,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => a.Cpu.CpuUsagePercentage) * 100,
                                               0d,
                                               id,
                                               $"CPU (rrd {thresholdHost.TimeSeries} AVERAGE)")],
                       true,
                       false);

        CheckThreshold(result,
                       thresholdHost.Memory,
                       "WV0002",
                       context,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => Convert.ToDouble(a.Memory.MemoryUsage)),
                                               rrdData.Average(a => Convert.ToDouble(a.Memory.MemorySize)),
                                               id,
                                               $"Memory (rrd {thresholdHost.TimeSeries} AVERAGE)")],
                       false,
                       true);

        CheckThreshold(result,
                       thresholdHost.Network,
                       "WV0002",
                       context,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => a.NetIO.NetIn),
                                               0d,
                                               id,
                                               $"NetIn (rrd {thresholdHost.TimeSeries} AVERAGE)")],
                       true,
                       false);

        CheckThreshold(result,
                       thresholdHost.Network,
                       "WV0002",
                       context,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => a.NetIO.NetOut),
                                               0d,
                                               id,
                                               $"NetOut (rrd {thresholdHost.TimeSeries} AVERAGE)")],
                       true,
                       false);
    }

    private static void CheckNodeRrd(List<DiagnosticResult> result,
                                     Settings settings,
                                     string id,
                                     IEnumerable<NodeRrdData> rrdData)
    {
        CheckThresholdHost(result,
                           settings.Node,
                           DiagnosticResultContext.Node,
                           id,
                           rrdData.Select(a => new ThresholdRddData(a, a, a)));

        CheckThreshold(result,
                       settings.Node.Cpu,
                       "WV0002",
                       DiagnosticResultContext.Node,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => a.IoWait) * 100,
                                               0d,
                                               id,
                                               $"IOWait (rrd {settings.Node.TimeSeries} AVERAGE)")],
                       true,
                       false);

        CheckThreshold(result,
                       settings.Storage.Threshold,
                       "WV0002",
                       DiagnosticResultContext.Node,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => a.RootUsage),
                                               rrdData.Average(a => a.RootSize),
                                               id,
                                               $"Root space (rrd {settings.Node.TimeSeries} AVERAGE)")],
                       false,
                       true);

        CheckThreshold(result,
                       settings.Storage.Threshold,
                       "WV0002",
                       DiagnosticResultContext.Node,
                       "Usage",
                       [new ThresholdDataPoint(rrdData.Average(a => a.SwapUsage),
                                               rrdData.Average(a => Convert.ToDouble(a.SwapSize)),
                                               id,
                                               $"SWAP (rrd {settings.Node.TimeSeries} AVERAGE)")],
                       false,
                       true);
    }

    private record ThresholdDataPoint(double Usage, double Size, string Id, string PrefixDescription);


    private static void CheckThreshold(List<DiagnosticResult> result,
                                       SettingsThreshold<double> threshold,
                                       string errorCode,
                                       DiagnosticResultContext context,
                                       string subContext,
                                       IEnumerable<ThresholdDataPoint> data,
                                       bool isValue,
                                       bool formatByte)
    {
        if (threshold.Warning == 0 || threshold.Critical == 0) { return; }

        var ranges = new[] { threshold.Warning, threshold.Critical, threshold.Critical * 100 };
        var gravity = new[] { DiagnosticResultGravity.Warning, DiagnosticResultGravity.Critical };

        for (int i = 0; i < 2; i++)
        {
            double GetValue(double usage, double size) => Math.Round(isValue ? usage : usage / size * 100.0, 1);

            string MakeDescription(string prefix, double usage, double size)
            {
                var txt = $"{prefix} usage {GetValue(usage, size)}%";
                if (formatByte) { txt += $" - {FormatHelper.FromBytes(usage)} of {FormatHelper.FromBytes(size)}"; }
                return txt;
            }

            result.AddRange(data.Where(a => GetValue(a.Usage, a.Size) >= ranges[i]
                                            && GetValue(a.Usage, a.Size) < ranges[i + 1])
                                .Select(a => new DiagnosticResult
                                {
                                    Id = a.Id,
                                    ErrorCode = errorCode,
                                    Description = MakeDescription(a.PrefixDescription, a.Usage, a.Size),
                                    Context = context,
                                    SubContext = subContext,
                                    Gravity = gravity[i],
                                }));
        }
    }
}
