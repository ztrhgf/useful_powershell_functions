function Get-CMLog {
    <#
    .SYNOPSIS
    Function for easy opening of SCCM logs.

    You have two options to define what log(s) you want to open:
     - by specifying AREA of your problem
     - by specifying NAME of the LOG(S)

    .DESCRIPTION
    Function for easy opening of SCCM logs.

    You have two options to define what log(s) you want to open:
     - by specifying AREA of your problem
     - by specifying NAME of the LOG(S)

    Benefits of using AREA approach:
     - you don't have to remember which logs are for which type of problem
     - you don't have to remember where such logs are stored

    Benefits of using LOG NAME approach:
     - you don't have to remember where such logs are stored

    General benefits of using this function:
     - description for each log is outputted
      - it is retrieved from https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files#BKMK_ServerLogs and cached locally so ongoing runs will be much faster!
     - function supports opening of archived logs
     - best possible log viewer application will be used
      - Sorted by preference: 'Configuration Manager Support Center Log Viewer', 'Support Center OneTrace', CMTrace or as a last resort in default associated program

    How to get the log viewers:
    - 'Configuration Manager Support Center Log Viewer' and 'Support Center OneTrace' can be installed via 'C:\Program Files\Microsoft Configuration Manager\tools\SupportCenter\supportcenterinstaller.msi' (saved on your SCCM server) or by installing SCCM Administrator console.
    - CMTrace is installed by default with SCCM Client

    .PARAMETER computerName
    Name of computer where CLIENT logs should be obtained.
    In case the problem is related to SCCM server, this parameter will be ignored.

    .PARAMETER area
    What area (problem) you want to show logs from.

    Possible values:
    ApplicationDiscovery
    ApplicationDownload
    ApplicationInstallation
    ApplicationManagement
    ApplicationMetering
    AssetIntelligence
    BackupAndRecovery
    BootImageUpdate
    CertificateEnrollment
    ClientInstallation
    ClientNotification
    ClientPush
    CMG
    CMGClientTraffic
    CMGDeployments
    CMGHealth
    Co-Management
    Compliance
    ComplianceSettingsAndCompanyResourceAccess
    ConfigurationManagerConsole
    ContentDistribution
    ContentManagement
    DesktopAnalytics
    Discovery
    EndpointAnalytics
    EndpointProtection
    ExchangeServerConnector
    Extensions
    Inventory
    InventoryProcessing
    Metering
    Migration
    MobileDeviceLegacy
    MobileDevicesEnrollment
    NotificationClient
    NotificationServer
    NotificationServerInstall
    OSDeployment
    OSDeployment_clientPerspective
    PackagesAndPrograms
    PolicyProcessing
    PowerManagement
    PXE
    RemoteControl
    Reporting
    Role-basedAdministration
    SoftwareMetering
    SoftwareUpdates
    WindowsServicing
    WindowsUpdateAgent
    WOL
    WSUSServer

    .PARAMETER logName
    Name of the log(s) you want to open.
    Function itself knows where log(s) are stored, so just name is enough.

    Possible values:
    ADALOperationProvider, adctrl, ADForestDisc, adminservice, AdminUI.ExtensionInstaller, ADService, adsgdis, adsysdis, adusrdis, aikbmgr, AIUpdateSvc, AIUSMSI, AIUSSetup, AlternateHandler, AppDiscovery, AppEnforce, AppGroupHandler, AppIntentEval, AssetAdvisor, BgbHttpProxy, bgbisapiMSI, bgbmgr, BGBServer, BgbSetup, BitLockerManagementHandler, BusinessAppProcessWorker, CAS, CBS, ccm, CCM_STS, Ccm32BitLauncher, CCMAgent, CCMClient, CcmEval, CcmEvalTask, CcmExec, CcmIsapi, CcmMessaging, CcmNotificationAgent, CCMNotificationAgent, CCMNotifications, ccmperf, Ccmperf, CCMPrefPane, CcmRepair, CcmRestart, Ccmsdkprovider, CCMSDKProvider, ccmsetup, ccmsetup-ccmeval, ccmsqlce, CcmUsrCse, CCMVDIProvider, CertEnrollAgent, CertificateMaintenance, CertMgr, CIAgent, Cidm, CIDownloader, CIStateStore, CIStore, CITaskManager, CITaskMgr, client.msi, client.msi_uninstall, ClientAuth, ClientIDManagerStartup, ClientLocation, ClientServicing, CloudDP, CloudMgr, Cloudusersync, CMBITSManager, CMGContentService, CMGHttpHandler, CMGService, CMGSetup, CMHttpsReadiness, CmRcService, CMRcViewer, CollectionAADGroupSyncWorker, CollEval, colleval, CoManagementHandler, ComplRelayAgent, compmon, compsumm, ComRegSetup, ConfigMgrAdminUISetup, ConfigMgrPrereq, ConfigMgrSetup, ConfigMgrSetupWizard, ContentTransferManager, CreateTSMedia, Crp, Crpctrl, Crpmsi, Crpsetup, dataldr, Dataldr, DataTransferService, DCMAgent, DCMReporting, DcmWmiProvider, ddm, DeltaDownload, despool, Diagnostics, DISM, Dism, dism, distmgr, Distmgr, DmCertEnroll, DMCertResp.htm, DmClientHealth, DmClientRegistration, DmClientSetup, DmClientXfer, DmCommonInstaller, DmInstaller, DmpDatastore, DmpDiscovery, Dmpdownloader, DmpHardware, DmpIsapi, dmpmsi, DMPRP, DMPSetup, DmpSoftware, DmpStatus, dmpuploader, Dmpuploader, DmSvc, DriverCatalog, DWSSMSI, DWSSSetup, easdisc, EndpointConnectivityCheckWorker, EndpointProtectionAgent, enrollmentservice, enrollmentweb, EnrollSrv, enrollsrvMSI, EnrollWeb, enrollwebMSI, EPCtrlMgr, EPMgr, EPSetup, execmgr, ExpressionSolver, ExternalEventAgent, ExternalNotificationsWorker, FeatureExtensionInstaller, FileBITS, FileSystemFile, FspIsapi, fspmgr, fspMSI, FSPStateMessage, hman, Change, chmgr, Inboxast, inboxmgr, inboxmon, InternetProxy, InventoryAgent, InventoryProvider, invproc, loadstate, LocationCache, LocationServices, M365ADeploymentPlanWorker, M365ADeviceHealthWorker, M365AHandler, M365AUploadWorker, MaintenanceCoordinator, ManagedProvider, mcsexec, mcsisapi, mcsmgr, MCSMSI, Mcsperf, mcsprv, MCSSetup, Microsoft.ConfigMgrDataWarehouse, MicrosoftPolicyPlatformSetup.msi, Mifprovider, migmctrl, MP_ClientIDManager, MP_CliReg, MP_Ddr, MP_DriverManager, MP_Framework, MP_GetAuth, MP_GetPolicy, MP_Hinv, MP_Location, MP_OOBMgr, MP_Policy, MP_RegistrationManager, MP_Relay, MP_RelayMsgMgr, MP_Retry, MP_Sinv, MP_SinvCollFile, MP_Status, mpcontrol, mpfdm, mpMSI, MPSetup, mtrmgr, MVLSImport, NDESPlugin, netdisc, NotiCtrl, ntsvrdis, Objreplmgr, objreplmgr, offermgr, offersum, OfflineServicingMgr, outboxmon, outgoingcontentmanager, PatchDownloader, PatchRepair, PerfSetup, PkgXferMgr, PolicyAgent, PolicyAgentProvider, PolicyEvaluator, PolicyPlatformClient, policypv, PolicyPV, PolicySdk, PrestageContent, PullDP, Pwrmgmt, pwrmgmt, PwrProvider, rcmctrl, RebootCoordinator, replmgr, ResourceExplorer, RESTPROVIDERSetup, ruleengine, ScanAgent, scanstate, SCClient, SCNotify, Scripts, SdmAgent, sender, SensorEndpoint, SensorManagedProvider, SensorWmiProvider, ServiceConnectionTool, ServiceWindowManager, SettingsAgent, Setupact, setupact, Setupapi, Setuperr, setuppolicyevaluator, schedule, Scheduler, sinvproc, sitecomp, Sitecomp, sitectrl, sitestat, SleepAgent, smpisapi, Smpmgr, smpmsi, smpperf, SMS_AZUREAD_DISCOVERY_AGENT, SMS_BOOTSTRAP, SMS_BUSINESS_APP_PROCESS_MANAGER, SMS_Cloud_ProxyConnector, SMS_CLOUDCONNECTION, SMS_DataEngine, SMS_DM, SMS_ImplicitUninstall, SMS_ISVUPDATES_SYNCAGENT, SMS_MESSAGE_PROCESSING_ENGINE, SMS_OrchestrationGroup, SMS_PhasedDeployment, SMS_REST_PROVIDER, SmsAdminUI, smsbkup, Smsbkup, SmsClientMethodProvider, smscliui, smsdbmon, SMSdpmon, smsdpprov, smsdpusage, SMSENROLLSRVSetup, SMSENROLLWEBSetup, smsexec, SMSFSPSetup, Smsprov, SMSProv, smspxe, smssmpsetup, smssqlbkup, Smsts, smstsvc, Smswriter, SmsWusHandler, SoftwareCenterSystemTasks, SoftwareDistribution, SrcUpdateMgr, srsrp, srsrpMSI, srsrpsetup, SrvBoot, StateMessage, StateMessageProvider, statesys, Statesys, statmgr, StatusAgent, SUPSetup, swmproc, SWMTRReportGen, TaskSequenceProvider, TSAgent, TSDTHandler, UpdatesDeployment, UpdatesHandler, UpdatesStore, UserAffinity, UserAffinityProvider, UserService, UXAnalyticsUploadWorker, VCRedist_x64_Install, VCRedist_x86_Install, VirtualApp, wakeprxy-install, wakeprxy-uninstall, WCM, Wedmtrace, WindowsUpdate, wolcmgr, wolmgr, WsfbSyncWorker, WSUSCtrl, wsyncmgr, WUAHandler, WUSSyncXML


    .PARAMETER maxHistory
    How much archived logs you want to see.
    Default is 0.

    .PARAMETER SCCMServer
    Name of the SCCM server.
    Needed in case the opened log is stored on the SCCM server, not client.
    To open server side logs admin share (C$) is used, so this function has to be run with appropriate rights.

    Default is $_SCCMServer.

    .PARAMETER WSUSServer
    Name of the WSUS server.
    Needed in case the opened log is stored on the WSUS server, not client.

    If not specified value from SCCMServer parameter will be used.

    .PARAMETER serviceConnectionPointServer
    Name of the Service Connection Point server.
    Needed in case the opened log is stored on the Service Connection Point server, not client.

    If not specified value from SCCMServer parameter will be used.

    .EXAMPLE
    Get-CMLog -area ApplicationDiscovery

    Opens all logs on this computer related to application discovery.

    .EXAMPLE
    Get-CMLog -area ApplicationDiscovery -maxHistory 3

    Opens all logs on this computer related to application discovery. Including archived ones (but at maximum 3 latest for each log).

    .EXAMPLE
    Get-CMLog -computerName PC01 -area ApplicationInstallation

    Opens all logs on PC01 related to application installation.

    .EXAMPLE
    Get-CMLog -logName CcmEval, CcmExec

    Opens logs CcmEval, CcmExec.

    .EXAMPLE
    Get-CMLog -area PXE -SCCMServer SCCM01

    Opens all logs related to PXE. If such logs are stored on SCCM server they will be searched on 'SCCM01'.

    .NOTES
    Author: @AndrewZtrhgf

    To add new (problem) area:
        - add its name to ValidateSet of $area parameter
        - define what logs should be opened in $areaDetails
        - check $logDetails that it defines path where are these new logs saved

    List of all SCCM logs https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files.
    #>

    [CmdletBinding(DefaultParameterSetName = 'area')]
    param (
        [Parameter(Position = 0)]
        [string] $computerName,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "area")]
        [ValidateSet('ApplicationDiscovery', 'ApplicationDownload', 'ApplicationInstallation', 'ApplicationManagement', 'ApplicationMetering', 'AssetIntelligence', 'BackupAndRecovery', 'BootImageUpdate', 'CertificateEnrollment', 'ClientInstallation', 'ClientNotification', 'ClientPush', 'CMG', 'CMGClientTraffic', 'CMGDeployments', 'CMGHealth', 'Co-Management', 'Compliance', 'ComplianceSettingsAndCompanyResourceAccess', 'ConfigurationManagerConsole', 'ContentDistribution', 'ContentManagement', 'DesktopAnalytics', 'Discovery', 'EndpointAnalytics', 'EndpointProtection', 'ExchangeServerConnector', 'Extensions', 'Inventory', 'InventoryProcessing', 'Metering', 'Migration', 'MobileDeviceLegacy', 'MobileDevicesEnrollment', 'NotificationClient', 'NotificationServer', 'NotificationServerInstall', 'OSDeployment', 'OSDeployment_clientPerspective', 'PackagesAndPrograms', 'PolicyProcessing', 'PowerManagement', 'PXE', 'RemoteControl', 'Reporting', 'Role-basedAdministration', 'SoftwareMetering', 'SoftwareUpdates', 'WindowsServicing', 'WindowsUpdateAgent', 'WOL', 'WSUSServer')]
        [Alias("problem")]
        [string] $area,

        [Parameter(Mandatory = $true, Position = 1, ParameterSetName = "logName")]
        [ValidateSet('ADALOperationProvider', 'adctrl', 'ADForestDisc', 'adminservice', 'AdminUI.ExtensionInstaller', 'ADService', 'adsgdis', 'adsysdis', 'adusrdis', 'aikbmgr', 'AIUpdateSvc', 'AIUSMSI', 'AIUSSetup', 'AlternateHandler', 'AppDiscovery', 'AppEnforce', 'AppGroupHandler', 'AppIntentEval', 'AssetAdvisor', 'BgbHttpProxy', 'bgbisapiMSI', 'bgbmgr', 'BGBServer', 'BgbSetup', 'BitLockerManagementHandler', 'BusinessAppProcessWorker', 'CAS', 'CBS', 'ccm', 'CCM_STS', 'Ccm32BitLauncher', 'CCMAgent', 'CCMClient', 'CcmEval', 'CcmEvalTask', 'CcmExec', 'CcmIsapi', 'CcmMessaging', 'CcmNotificationAgent', 'CCMNotificationAgent', 'CCMNotifications', 'ccmperf', 'Ccmperf', 'CCMPrefPane', 'CcmRepair', 'CcmRestart', 'Ccmsdkprovider', 'CCMSDKProvider', 'ccmsetup', 'ccmsetup-ccmeval', 'ccmsqlce', 'CcmUsrCse', 'CCMVDIProvider', 'CertEnrollAgent', 'CertificateMaintenance', 'CertMgr', 'CIAgent', 'Cidm', 'CIDownloader', 'CIStateStore', 'CIStore', 'CITaskManager', 'CITaskMgr', 'client.msi', 'client.msi_uninstall', 'ClientAuth', 'ClientIDManagerStartup', 'ClientLocation', 'ClientServicing', 'CloudDP', 'CloudMgr', 'Cloudusersync', 'CMBITSManager', 'CMGContentService', 'CMGHttpHandler', 'CMGService', 'CMGSetup', 'CMHttpsReadiness', 'CmRcService', 'CMRcViewer', 'CollectionAADGroupSyncWorker', 'CollEval', 'colleval', 'CoManagementHandler', 'ComplRelayAgent', 'compmon', 'compsumm', 'ComRegSetup', 'ConfigMgrAdminUISetup', 'ConfigMgrPrereq', 'ConfigMgrSetup', 'ConfigMgrSetupWizard', 'ContentTransferManager', 'CreateTSMedia', 'Crp', 'Crpctrl', 'Crpmsi', 'Crpsetup', 'dataldr', 'Dataldr', 'DataTransferService', 'DCMAgent', 'DCMReporting', 'DcmWmiProvider', 'ddm', 'DeltaDownload', 'despool', 'Diagnostics', 'DISM', 'Dism', 'dism', 'distmgr', 'Distmgr', 'DmCertEnroll', 'DMCertResp.htm', 'DmClientHealth', 'DmClientRegistration', 'DmClientSetup', 'DmClientXfer', 'DmCommonInstaller', 'DmInstaller', 'DmpDatastore', 'DmpDiscovery', 'Dmpdownloader', 'DmpHardware', 'DmpIsapi', 'dmpmsi', 'DMPRP', 'DMPSetup', 'DmpSoftware', 'DmpStatus', 'dmpuploader', 'Dmpuploader', 'DmSvc', 'DriverCatalog', 'DWSSMSI', 'DWSSSetup', 'easdisc', 'EndpointConnectivityCheckWorker', 'EndpointProtectionAgent', 'enrollmentservice', 'enrollmentweb', 'EnrollSrv', 'enrollsrvMSI', 'EnrollWeb', 'enrollwebMSI', 'EPCtrlMgr', 'EPMgr', 'EPSetup', 'execmgr', 'ExpressionSolver', 'ExternalEventAgent', 'ExternalNotificationsWorker', 'FeatureExtensionInstaller', 'FileBITS', 'FileSystemFile', 'FspIsapi', 'fspmgr', 'fspMSI', 'FSPStateMessage', 'hman', 'Change', 'chmgr', 'Inboxast', 'inboxmgr', 'inboxmon', 'InternetProxy', 'InventoryAgent', 'InventoryProvider', 'invproc', 'loadstate', 'LocationCache', 'LocationServices', 'M365ADeploymentPlanWorker', 'M365ADeviceHealthWorker', 'M365AHandler', 'M365AUploadWorker', 'MaintenanceCoordinator', 'ManagedProvider', 'mcsexec', 'mcsisapi', 'mcsmgr', 'MCSMSI', 'Mcsperf', 'mcsprv', 'MCSSetup', 'Microsoft.ConfigMgrDataWarehouse', 'MicrosoftPolicyPlatformSetup.msi', 'Mifprovider', 'migmctrl', 'MP_ClientIDManager', 'MP_CliReg', 'MP_Ddr', 'MP_DriverManager', 'MP_Framework', 'MP_GetAuth', 'MP_GetPolicy', 'MP_Hinv', 'MP_Location', 'MP_OOBMgr', 'MP_Policy', 'MP_RegistrationManager', 'MP_Relay', 'MP_RelayMsgMgr', 'MP_Retry', 'MP_Sinv', 'MP_SinvCollFile', 'MP_Status', 'mpcontrol', 'mpfdm', 'mpMSI', 'MPSetup', 'mtrmgr', 'MVLSImport', 'NDESPlugin', 'netdisc', 'NotiCtrl', 'ntsvrdis', 'Objreplmgr', 'objreplmgr', 'offermgr', 'offersum', 'OfflineServicingMgr', 'outboxmon', 'outgoingcontentmanager', 'PatchDownloader', 'PatchRepair', 'PerfSetup', 'PkgXferMgr', 'PolicyAgent', 'PolicyAgentProvider', 'PolicyEvaluator', 'PolicyPlatformClient', 'policypv', 'PolicyPV', 'PolicySdk', 'PrestageContent', 'PullDP', 'Pwrmgmt', 'pwrmgmt', 'PwrProvider', 'rcmctrl', 'RebootCoordinator', 'replmgr', 'ResourceExplorer', 'RESTPROVIDERSetup', 'ruleengine', 'ScanAgent', 'scanstate', 'SCClient', 'SCNotify', 'Scripts', 'SdmAgent', 'sender', 'SensorEndpoint', 'SensorManagedProvider', 'SensorWmiProvider', 'ServiceConnectionTool', 'ServiceWindowManager', 'SettingsAgent', 'Setupact', 'setupact', 'Setupapi', 'Setuperr', 'setuppolicyevaluator', 'schedule', 'Scheduler', 'sinvproc', 'sitecomp', 'Sitecomp', 'sitectrl', 'sitestat', 'SleepAgent', 'smpisapi', 'Smpmgr', 'smpmsi', 'smpperf', 'SMS_AZUREAD_DISCOVERY_AGENT', 'SMS_BOOTSTRAP', 'SMS_BUSINESS_APP_PROCESS_MANAGER', 'SMS_Cloud_ProxyConnector', 'SMS_CLOUDCONNECTION', 'SMS_DataEngine', 'SMS_DM', 'SMS_ImplicitUninstall', 'SMS_ISVUPDATES_SYNCAGENT', 'SMS_MESSAGE_PROCESSING_ENGINE', 'SMS_OrchestrationGroup', 'SMS_PhasedDeployment', 'SMS_REST_PROVIDER', 'SmsAdminUI', 'smsbkup', 'Smsbkup', 'SmsClientMethodProvider', 'smscliui', 'smsdbmon', 'SMSdpmon', 'smsdpprov', 'smsdpusage', 'SMSENROLLSRVSetup', 'SMSENROLLWEBSetup', 'smsexec', 'SMSFSPSetup', 'Smsprov', 'SMSProv', 'smspxe', 'smssmpsetup', 'smssqlbkup', 'Smsts', 'smstsvc', 'Smswriter', 'SmsWusHandler', 'SoftwareCenterSystemTasks', 'SoftwareDistribution', 'SrcUpdateMgr', 'srsrp', 'srsrpMSI', 'srsrpsetup', 'SrvBoot', 'StateMessage', 'StateMessageProvider', 'statesys', 'Statesys', 'statmgr', 'StatusAgent', 'SUPSetup', 'swmproc', 'SWMTRReportGen', 'TaskSequenceProvider', 'TSAgent', 'TSDTHandler', 'UpdatesDeployment', 'UpdatesHandler', 'UpdatesStore', 'UserAffinity', 'UserAffinityProvider', 'UserService', 'UXAnalyticsUploadWorker', 'VCRedist_x64_Install', 'VCRedist_x86_Install', 'VirtualApp', 'wakeprxy-install', 'wakeprxy-uninstall', 'WCM', 'Wedmtrace', 'WindowsUpdate', 'wolcmgr', 'wolmgr', 'WsfbSyncWorker', 'WSUSCtrl', 'wsyncmgr', 'WUAHandler', 'WUSSyncXML')]
        [ValidateScript( {
                If ($_ -match "\.log$") {
                    throw "Enter log name without extension (.log)"
                } else {
                    $true
                }
            })]
        [string[]] $logName,

        [ValidateRange(0, 100)]
        [int] $maxHistory = 0,

        [ValidateNotNullOrEmpty()]
        [string] $SCCMServer = $_SCCMServer,

        [string] $WSUSServer,

        [string] $serviceConnectionPointServer
    )

    #region prepare
    if (!$serviceConnectionPointServer -and $SCCMServer) {
        Write-Verbose "Setting serviceConnectionPointServer parameter to '$SCCMServer'"
        $serviceConnectionPointServer = $SCCMServer
    }

    if (!$WSUSServer -and $SCCMServer) {
        Write-Verbose "Setting WSUSServer parameter to '$SCCMServer'"
        $WSUSServer = $SCCMServer
    }

    #region define common folders where logs are stored
    # client's log location
    if ($computerName) {
        # client's log location
        $clientLog = "\\$computerName\C$\Windows\CCM\Logs"
        # client's setup log location
        $clientSetupLog = "\\$computerName\C$\Windows\ccmsetup\Logs"
        # Remote Control log location (stored on computer that runs Remote Control)
        $remoteControlLog = "\\$computerName\C$\Windows\Temp"
        # SCCM console log location (stored on computer that runs SCCM console)
        $sccmConsoleLog = "\\$computerName\C$\Program Files (x86)\Microsoft Endpoint Manager\AdminConsole\AdminUILog"
    } else {
        # client's log location
        $clientLog = "$env:windir\CCM\Logs"
        # client's setup log location
        $clientSetupLog = "$env:windir\ccmsetup\Logs"
        # Remote Control log location (stored on computer that runs Remote Control)
        $remoteControlLog = "$env:windir\Temp"
        # SCCM console log location (stored on computer that runs SCCM console)
        $sccmConsoleLog = "${env:ProgramFiles(x86)}\Microsoft Endpoint Manager\AdminConsole\AdminUILog"
    }
    # client's SMSTS log location
    $clientSMSTSLog = "$clientLog\SMSTSLog"

    # server's log locations
    $serverLog = "\\$SCCMServer\C$\Program Files\SMS_CCM\Logs"
    $serverLog2 = "\\$SCCMServer\C$\Program Files\Microsoft Configuration Manager\Logs"
    $serverDISMLog = "\\$SCCMServer\C$\Windows\Logs\DISM"
    $WSUSLog = "\\$WSUSServer\C$\Program Files\Update Services\LogFiles"

    # Service Connection Point location
    $serviceConnectionPointLog = "\\$serviceConnectionPointServer\C$\Program Files\Configuration Manager\Logs\M365A"
    #endregion define common folders where logs are stored

    #region define where specific logs are stored
    $logDetails = @(
        [PSCustomObject]@{
            logName   = @('AdminUI.ExtensionInstaller', 'ConfigMgrAdminUISetup', 'CreateTSMedia', 'FeatureExtensionInstaller', 'ResourceExplorer', 'SmsAdminUI')
            logFolder = $sccmConsoleLog
        },

        [PSCustomObject]@{
            logName   = @('CMRcViewer')
            logFolder = $remoteControlLog
        },

        [PSCustomObject]@{
            logName   = @('ccmsetup-ccmeval', 'ccmsetup', 'CcmRepair', 'client.msi', 'client.msi_uninstall', 'MicrosoftPolicyPlatformSetup.msi', 'PatchRepair', 'VCRedist_x64_Install', 'VCRedist_x86_Install')
            logFolder = $clientSetupLog
        },

        [PSCustomObject]@{
            logName   = @('ADALOperationProvider', 'BitLockerManagementHandler', 'CAS', 'Ccm32BitLauncher', 'CcmEval', 'CcmEvalTask', 'CcmExec', 'CcmMessaging', 'CCMNotificationAgent', 'Ccmperf', 'CcmRestart', 'CCMSDKProvider', 'ccmsqlce', 'CcmUsrCse', 'CCMVDIProvider', 'CertEnrollAgent', 'CertificateMaintenance', 'CIAgent', 'CIDownloader', 'CIStateStore', 'CIStore', 'CITaskMgr', 'ClientAuth', 'ClientIDManagerStartup', 'ClientLocation', 'ClientServicing', 'CMBITSManager', 'CMHttpsReadiness', 'CmRcService', 'CoManagementHandler', 'ComplRelayAgent', 'ContentTransferManager', 'DataTransferService', 'DCMAgent', 'DCMReporting', 'DcmWmiProvider', 'DeltaDownload', 'Diagnostics', 'EndpointProtectionAgent', 'execmgr', 'ExpressionSolver', 'ExternalEventAgent', 'FileBITS', 'FileSystemFile', 'FSPStateMessage', 'InternetProxy', 'InventoryAgent', 'InventoryProvider', 'LocationCache', 'LocationServices', 'M365AHandler', 'MaintenanceCoordinator', 'Mifprovider', 'mtrmgr', 'PolicyAgent', 'PolicyAgentProvider', 'PolicyEvaluator', 'PolicyPlatformClient', 'PolicySdk', 'Pwrmgmt', 'PwrProvider', 'SCClient', 'Scheduler', 'SCNotify', 'Scripts', 'SensorWmiProvider', 'SensorEndpoint', 'SensorManagedProvider', 'setuppolicyevaluator', 'SleepAgent', 'SmsClientMethodProvider', 'smscliui', 'SrcUpdateMgr', 'StateMessageProvider', 'StatusAgent', 'SWMTRReportGen', 'UserAffinity', 'UserAffinityProvider', 'VirtualApp', 'Wedmtrace', 'wakeprxy-install', 'wakeprxy-uninstall', 'ClientServicing', 'CCMClient', 'CCMAgent', 'CCMNotifications', 'CCMPrefPane', 'AppIntentEval', 'AppDiscovery', 'AppEnforce', 'AppGroupHandler', 'Ccmsdkprovider', 'SettingsAgent', 'SoftwareCenterSystemTasks', 'TSDTHandler', 'execmgr', 'AssetAdvisor', 'BgbHttpProxy', 'CcmNotificationAgent', 'CIAgent', 'CITaskManager', 'DCMAgent', 'DCMReporting', 'DcmWmiProvider', 'M365AHandler', 'InventoryAgent', 'SensorWmiProvider', 'SensorEndpoint', 'SensorManagedProvider', 'EndpointProtectionAgent', 'mtrmgr', 'SWMTRReportGen', 'DmCertEnroll', 'DMCertResp.htm', 'DmClientSetup', 'DmClientXfer', 'DmCommonInstaller', 'DmInstaller', 'DmSvc', 'CAS', 'ccmsetup', 'Setupact', 'Setupapi', 'Setuperr', 'smpisapi', 'TSAgent', 'loadstate', 'scanstate', 'pwrmgmt', 'AlternateHandler', 'ccmperf', 'DeltaDownload', 'PolicyEvaluator', 'RebootCoordinator', 'ScanAgent', 'SdmAgent', 'ServiceWindowManager', 'SmsWusHandler', 'StateMessage', 'UpdatesDeployment', 'UpdatesHandler', 'UpdatesStore', 'WUAHandler', 'CBS', 'DISM', 'setupact', 'WindowsUpdate')
            logFolder = $clientLog
        },

        [PSCustomObject]@{
            logName   = @('Smsts')
            logFolder = $clientSMSTSLog
        },

        [PSCustomObject]@{
            logName   = @('adctrl', 'ADForestDisc', 'adminservice', 'ADService', 'adsgdis', 'adsysdis', 'adusrdis', 'BusinessAppProcessWorker', 'ccm', 'CertMgr', 'chmgr', 'Cidm', 'CollectionAADGroupSyncWorker', 'colleval', 'compmon', 'compsumm', 'ComRegSetup', 'dataldr', 'ddm', 'despool', 'distmgr', 'EPCtrlMgr', 'EPMgr', 'EPSetup', 'EnrollSrv', 'EnrollWeb', 'ExternalNotificationsWorker', 'fspmgr', 'hman', 'Inboxast', 'inboxmgr', 'inboxmon', 'invproc', 'migmctrl', 'mpcontrol', 'mpfdm', 'mpMSI', 'MPSetup', 'netdisc', 'NotiCtrl', 'ntsvrdis', 'Objreplmgr', 'offermgr', 'offersum', 'OfflineServicingMgr', 'outboxmon', 'PerfSetup', 'PkgXferMgr', 'policypv', 'rcmctrl', 'replmgr', 'RESTPROVIDERSetup', 'ruleengine', 'schedule', 'sender', 'sinvproc', 'sitecomp', 'sitectrl', 'sitestat', 'SMS_AZUREAD_DISCOVERY_AGENT', 'SMS_BUSINESS_APP_PROCESS_MANAGER', 'SMS_DataEngine', 'SMS_ISVUPDATES_SYNCAGENT', 'SMS_MESSAGE_PROCESSING_ENGINE', 'SMS_OrchestrationGroup', 'SMS_PhasedDeployment', 'SMS_REST_PROVIDER', 'smsbkup', 'smsdbmon', 'SMSENROLLSRVSetup', 'SMSENROLLWEBSetup', 'smsexec', 'SMSFSPSetup', 'SMSProv', 'srsrpMSI', 'srsrpsetup', 'statesys', 'statmgr', 'swmproc', 'UXAnalyticsUploadWorker', 'ConfigMgrPrereq', 'ConfigMgrSetup', 'ConfigMgrSetupWizard', 'SMS_BOOTSTRAP', 'smstsvc', 'DWSSMSI', 'DWSSSetup', 'Microsoft.ConfigMgrDataWarehouse', 'FspIsapi', 'fspMSI', 'CcmIsapi', 'CCM_STS', 'ClientAuth', 'MP_CliReg', 'MP_Ddr', 'MP_Framework', 'MP_GetAuth', 'MP_GetPolicy', 'MP_Hinv', 'MP_Location', 'MP_OOBMgr', 'MP_Policy', 'MP_RegistrationManager', 'MP_Relay', 'MP_RelayMsgMgr', 'MP_Retry', 'MP_Sinv', 'MP_SinvCollFile', 'MP_Status', 'UserService', 'CollEval', 'Cloudusersync', 'Dataldr', 'Distmgr', 'Dmpdownloader', 'Dmpuploader', 'EndpointConnectivityCheckWorker', 'WsfbSyncWorker', 'objreplmgr', 'PolicyPV', 'outgoingcontentmanager', 'ServiceConnectionTool', 'Sitecomp', 'SMS_CLOUDCONNECTION', 'Smsprov', 'SrvBoot', 'Statesys', 'PatchDownloader', 'SUPSetup', 'WCM', 'WSUSCtrl', 'wsyncmgr', 'WUSSyncXML', 'PrestageContent', 'SMS_ImplicitUninstall', 'SMSdpmon', 'aikbmgr', 'AIUpdateSvc', 'AIUSMSI', 'AIUSSetup', 'ManagedProvider', 'MVLSImport', 'Smsbkup', 'smssqlbkup', 'Smswriter', 'Crp', 'Crpctrl', 'Crpsetup', 'Crpmsi', 'NDESPlugin', 'bgbmgr', 'BGBServer', 'BgbSetup', 'bgbisapiMSI', 'CloudMgr', 'CMGSetup', 'CMGService', 'SMS_Cloud_ProxyConnector', 'CMGContentService', 'CMGHttpHandler', 'CloudDP', 'DataTransferService', 'PullDP', 'smsdpprov', 'smsdpusage', 'M365ADeploymentPlanWorker', 'M365ADeviceHealthWorker', 'M365AUploadWorker', 'DMPRP', 'dmpmsi', 'DMPSetup', 'enrollsrvMSI', 'enrollmentweb', 'enrollwebMSI', 'enrollmentservice', 'SMS_DM', 'easdisc', 'DmClientHealth', 'DmClientRegistration', 'DmpDatastore', 'DmpDiscovery', 'DmpHardware', 'DmpIsapi', 'DmpSoftware', 'DmpStatus', 'Dism', 'DriverCatalog', 'mcsisapi', 'mcsexec', 'mcsmgr', 'mcsprv', 'MCSSetup', 'MCSMSI', 'Mcsperf', 'MP_ClientIDManager', 'MP_DriverManager', 'Smpmgr', 'smpmsi', 'smpperf', 'smspxe', 'smssmpsetup', 'TaskSequenceProvider', 'srsrp', 'mtrmgr', 'wolcmgr', 'wolmgr', 'Change', 'SoftwareDistribution')
            logFolder = $serverLog, $serverLog2
        },

        [PSCustomObject]@{
            logName   = @('dism')
            logFolder = $serverDISMLog
        },

        [PSCustomObject]@{
            logName   = @('Change', 'SoftwareDistribution')
            logFolder = $WSUSLog
        },

        [PSCustomObject]@{
            logName   = @('Cloudusersync', 'Dmpdownloader', 'dmpuploader', 'EndpointConnectivityCheckWorker', 'M365ADeploymentPlanWorker', 'M365ADeviceHealthWorker', 'M365AUploadWorker', 'outgoingcontentmanager', 'SMS_CLOUDCONNECTION', 'SmsAdminUI', 'SrvBoot', 'WsfbSyncWorker')
            logFolder = $serviceConnectionPointLog
        }
    )
    #endregion define where specific logs are stored

    #region get best possible log viewer
    $CMLogViewer = "${env:ProgramFiles(x86)}\Microsoft Endpoint Manager\AdminConsole\bin\CMLogViewer.exe"
    $CMLogViewer2 = "${env:ProgramFiles(x86)}\Configuration Manager Support Center\CMLogViewer.exe"
    $CMPowerLogViewer = "${env:ProgramFiles(x86)}\Microsoft Endpoint Manager\AdminConsole\bin\CMPowerLogViewer.exe"
    $CMPowerLogViewer2 = "${env:ProgramFiles(x86)}\Configuration Manager Support Center\CMPowerLogViewer.exe"
    $CMTrace = "$env:windir\CCM\CMTrace.exe"

    if (Test-Path $CMLogViewer) {
        $viewer = $CMLogViewer
    } elseif (Test-Path $CMLogViewer2) {
        $viewer = $CMLogViewer2
    } elseif (Test-Path $CMPowerLogViewer) {
        $viewer = $CMPowerLogViewer
    } elseif (Test-Path $CMPowerLogViewer2) {
        $viewer = $CMPowerLogViewer2
    } elseif (Test-Path $CMTrace) {
        $viewer = $CMTrace
    }
    #endregion get best possible log viewer

    #region helper functions
    function ConvertFrom-HTMLTable {
        <#
        .SYNOPSIS
        Function for converting ComObject HTML object to common PowerShell object.

        .DESCRIPTION
        Function for converting ComObject HTML object to common PowerShell object.
        ComObject can be retrieved by (Invoke-WebRequest).parsedHtml or IHTMLDocument2_write methods.

        In case table is missing column names and number of columns is:
        - 2
            - Value in the first column will be used as object property 'Name'. Value in the second column will be therefore 'Value' of such property.
        - more than 2
            - Column names will be numbers starting from 1.

        .PARAMETER table
        ComObject representing HTML table.

        .PARAMETER tableName
        (optional) Name of the table.
        Will be added as TableName property to new PowerShell object.

        .EXAMPLE
        $actualContent = Invoke-WebRequest -Method GET -Headers $Headers -Uri "https://kentico.atlassian.net/wiki/rest/api/content/$pageID`?expand=body.storage"
        $table = $actualContent.ParsedHtml.getElementsByTagName('table')[0]
        $confluenceContent = @(ConvertFrom-HTMLTable $table)

        Will receive web page content >> filter out first table on that page >> convert it to PSObject

        .EXAMPLE
        $Source = Get-Content "C:\Users\Public\Documents\MDMDiagnostics\MDMDiagReport.html" -Raw
        $HTML = New-Object -Com "HTMLFile"
        $HTML.IHTMLDocument2_write($Source)
        $HTML.body.getElementsByTagName('table') | % {
            ConvertFrom-HTMLTable $_
        }

        Will get web page content from stored html file >> filter out all html tables from that page >> convert them to PSObjects
        #>

        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [System.__ComObject] $table,

            [string] $tableName
        )

        $twoColumnsWithoutName = 0

        if ($tableName) { $tableNameTxt = "'$tableName'" }

        $columnName = $table.getElementsByTagName("th") | % { $_.innerText -replace "^\s*|\s*$" }

        if (!$columnName) {
            $numberOfColumns = @($table.getElementsByTagName("tr")[0].getElementsByTagName("td")).count
            if ($numberOfColumns -eq 2) {
                ++$twoColumnsWithoutName
                Write-Verbose "Table $tableNameTxt has two columns without column names. Resultant object will use first column as objects property 'Name' and second as 'Value'"
            } elseif ($numberOfColumns) {
                Write-Warning "Table $tableNameTxt doesn't contain column names, numbers will be used instead"
                $columnName = 1..$numberOfColumns
            } else {
                throw "Table $tableNameTxt doesn't contain column names and summarization of columns failed"
            }
        }

        if ($twoColumnsWithoutName) {
            # table has two columns without names
            $property = [ordered]@{ }

            $table.getElementsByTagName("tr") | % {
                # read table per row and return object
                $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
                if ($columnValue) {
                    # use first column value as object property 'Name' and second as a 'Value'
                    $property.($columnValue[0]) = $columnValue[1]
                } else {
                    # row doesn't contain <td>
                }
            }
            if ($tableName) {
                $property.TableName = $tableName
            }

            New-Object -TypeName PSObject -Property $property
        } else {
            # table doesn't have two columns or they are named
            $table.getElementsByTagName("tr") | % {
                # read table per row and return object
                $columnValue = $_.getElementsByTagName("td") | % { $_.innerText -replace "^\s*|\s*$" }
                if ($columnValue) {
                    $property = [ordered]@{ }
                    $i = 0
                    $columnName | % {
                        $property.$_ = $columnValue[$i]
                        ++$i
                    }
                    if ($tableName) {
                        $property.TableName = $tableName
                    }

                    New-Object -TypeName PSObject -Property $property
                } else {
                    # row doesn't contain <td>, its probably row with column names
                }
            }
        }
    }

    function _getAndCacheLogDescription {
        $uri = "https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/hierarchy/log-files"
        Write-Verbose "Getting logs info from $uri"
        try {
            $pageContent = Invoke-WebRequest -Method GET -Uri $uri -ErrorAction Stop
        } catch {
            Write-Warning "Unable to get data from $uri. Description for the logs will not be shown."
            return
        }

        # on page some tables have 'Log Name' as column name and others have just 'Log'
        # also some logs are defined multiple times so remove duplicities
        $script:logDescription = $pageContent.ParsedHtml.getElementsByTagName('table') | % { ConvertFrom-HTMLTable $_ } | select @{n = 'LogName'; e = { if ($_.'Log Name') { ($_.'Log Name' -split "\s+")[0] } else { ($_.'Log' -split "\s+")[0] } } }, @{n = 'Description'; e = { $_.Description } } | sort -Unique -Property LogName

        # cache the results
        Write-Verbose "Caching data to '$cachedLogDescription'"
        $script:logDescription | Export-Clixml -Path $cachedLogDescription -Force
    }

    function _getLogDescription {
        param (
            [Parameter(Mandatory = $true)]
            [string[]] $logName,

            [switch] $secondRun
        )

        $logWithoutDescription = 'CMGHttpHandler', 'client.msi_uninstall'

        if ($script:logDescription) {
            if (!$secondRun) {
                Write-Host "Log(s) description #####################`n" -ForegroundColor Green
            }

            $logName | % {
                $lName = $_.trim()

                # log names on web page can be in these forms too
                # CCMAgent-<date_time>.log
                # SCClient_<domain>@<username>_1.log
                # SleepAgent_<domain>@SYSTEM_0.log
                $wantedLogDescription = $script:logDescription | ? LogName -Match "^$lName\.log$|^$lName[-_].+\.log$"

                if ($wantedLogDescription) {
                    # for better readibility output as string
                    $wantedLogDescription | % {
                        $_.LogName
                        " - " + $_.Description
                        ""
                    }
                } else {
                    if ($secondRun) {
                        Write-Warning "Unable to get description for $lName log."
                    } else {
                        if ($lName -in $logWithoutDescription) {
                            Write-Warning "For $lName there is no description."
                        } else {
                            Write-Warning "Unable to get description for $lName log. Trying to get newest data from Microsoft site"

                            _getAndCacheLogDescription

                            # try again
                            _getLogDescription $lName -secondRun # secondRun parameter to avoid infinite loop
                        }
                    }
                }
            }

            if (!$secondRun) {
                Write-Host "########################################" -ForegroundColor Green
            }
        }
    }

    function _openLog {
        param (
            [string[]] $logName
        )

        $logPath = @()

        $inaccessibleLogFolder = @()

        #region get log path
        foreach ($lName in $logName) {
            # most logs have static name but some are dynamic:
            # - CloudDP-<guid>.log
            # - SCClient_<domain>@<username>_1.log
            # - SCNotify_<domain>@<username>_1-<date_time>.log
            # - SleepAgent_<domain>@SYSTEM_0.log
            # - CCMClient-<date_time>.log
            # - CCMAgent-<date_time>.log
            # - CCMNotifications-<date_time>.log
            # - CCMPrefPane-<date_time>.log
            # - CMG-zzzxxxyyy-ProxyService_IN_0-CMGxxx.log

            Write-Verbose "Processing '$lName' log"

            if ($lName -eq 'CMRcViewer') {
                Write-Warning "Log 'CMRcViewer' is saved on the computer that runs the remote control viewer, in the %temp% folder. For sake of this function it is searched on computer defined in computerName parameter (a.k.a. $computerName)"
            }

            $logFolder = $logDetails | ? logName -Contains $lName | select -ExpandProperty logFolder
            if (!$logFolder) { throw "Undefined destination folder for log $lName. Define it inside this function in `$logDetails" }

            $wantedLog = $null

            # some logs are in multiple locations (therefore foreach)
            foreach ($lFolder in $logFolder) {
                if ($lFolder -in $inaccessibleLogFolder) {
                    Write-Verbose "Skipping inaccessible '$lFolder'"
                    continue
                }

                #region checks
                if (!$SCCMServer -and ($lFolder -in $serverLog, $serverDISMLog)) {
                    throw "You haven't specified SCCMServer parameter but log '$lName' is saved on SCCM server."
                }

                if (!$WSUSServer -and ($lFolder -in $WSUSLog)) {
                    throw "You haven't specified WSUSServer parameter but log '$lName' is saved on WSUS server."
                }

                if (!$serviceConnectionPointServer -and ($lFolder -in $serviceConnectionPointLog)) {
                    throw "You haven't specified serviceConnectionPointServer parameter but log '$lName' is saved on Service Connection Point server."
                }
                #endregion checks

                # get all possible log
                try {
                    # <log> OR <log>-<guid> OR <log>_<domain>@<username> OR <log>-<date_time> OR CMG-<tenantdata><log>
                    $regEscLog = [regex]::Escape($lName)
                    $availableLogs = Get-ChildItem $lFolder -Force -File -ErrorAction Stop | ? Name -Match "$regEscLog\.log?$|$regEscLog-[A-Z0-9-]+\.log?$|$regEscLog`_.+@.+\.log?$|$regEscLog-[0-9-]+\.log?$|CMG-.+$regEscLog" | Sort-Object LastWriteTime -Descending | Select-Object -ExpandProperty FullName
                } catch {
                    Write-Error "Unable to get logs from '$lFolder'. Error was: $_"
                    $inaccessibleLogFolder += $lFolder
                    continue
                }

                if ($availableLogs) {
                    #region add wanted log
                    # omit '.lo_' logs because they are archived logs
                    $wantedLog = $availableLogs | ? { $_ -match "\.log$" } | select -First 1

                    if ($wantedLog) {
                        Write-Verbose "`t- adding:`n'$wantedLog'"
                        $logPath += $wantedLog
                    }
                    #endregion add wanted log

                    #region add archived log(s)
                    if ($maxHistory -and $wantedLog) {
                        # $wantedLog is set means that I am searching in the right folder
                        $archivedLog = @($availableLogs | Select-Object -Skip 1 -First $maxHistory)

                        if ($archivedLog) {
                            Write-Verbose "`t- adding archive(s):`n$($archivedLog -join "`n")"
                            $logPath = @($logPath) + @($archivedLog) | Select-Object -Unique
                        } else {
                            Write-Verbose "`t- there are no archived versions"
                        }
                    }
                    #endregion add archived log(s)
                }
            }

            if (!$wantedLog) {
                Write-Warning "No '$lName' logs found in $(($logFolder | % {"'$_'"} ) -join ', ')"
            }
        }
        #endregion get log path

        #region open the log(s)
        if ($logPath) {
            if ($viewer -and $viewer -match "CMLogViewer\.exe$") {
                # open all logs in one CMLogViewer instance
                $quotedLog = ($logPath | % {
                        "`"$_`""
                    }) -join " "
                Start-Process $viewer -ArgumentList $quotedLog
            } elseif ($viewer -and $viewer -match "CMPowerLogViewer\.exe$") {
                # open all logs in one CMPowerLogViewer instance
                $quotedLog = ($logPath | % {
                        "`"$_`""
                    }) -join " "
                Start-Process $viewer -ArgumentList "--files $quotedLog"
            } else {
                # cmtrace (or notepad) don't support opening multiple logs in one instance, so open each log in separate viewer process
                foreach ($lPath in $logPath) {
                    if (!(Test-Path $lPath -ErrorAction SilentlyContinue)) {
                        continue
                    }

                    Write-Verbose "Opening $lPath"
                    if ($viewer -and $viewer -match "CMTrace\.exe$") {
                        # in case CMTrace viewer exists, use it
                        Start-Process $viewer -ArgumentList "`"$lPath`""
                    } else {
                        # use associated viewer
                        & $lPath
                    }
                }
            }
        } else {
            Write-Warning "There is no log to open"
        }
        #endregion open the log(s)
    }
    #endregion helper functions

    #region get log description from Microsoft documentation page
    $cachedLogDescription = "$env:TEMP\cachedLogDescription_8437973289.xml"
    $thresholdForGetNewData = 180
    $script:logDescription = $null

    if ((Test-Path $cachedLogDescription -ErrorAction SilentlyContinue) -and (Get-Item $cachedLogDescription).LastWriteTime -gt [datetime]::Now.AddDays(-$thresholdForGetNewData)) {
        # use cached version
        Write-Verbose "Use cached version of log information from $((Get-Item $cachedLogDescription).LastWriteTime)"
        $script:logDescription = Import-Clixml $cachedLogDescription
    } else {
        # get recent data and cache them
        try {
            _getAndCacheLogDescription
        } catch {
            Write-Warning $_
        }
    }
    #endregion get log description from Microsoft documentation page

    # hash where key is name of the area and value is hash with logs that should be opened and info that should be outputted
    # allowed keys in nested hash: log, writeHost, warningHost
    $areaDetails = @{
        "ApplicationInstallation"                    = @{
            log       = 'AppDiscovery', 'AppEnforce', 'AppIntentEval', 'Execmgr'
            writeHost = "More info at https://blogs.technet.microsoft.com/sudheesn/2011/01/31/troubleshooting-sccm-part-vi-software-distribution/"
        }

        "ApplicationDiscovery"                       = @{
            log = 'AppDiscovery'
        }

        "ApplicationDownload"                        = @{
            log       = 'DataTransferService'
            writeHost = "You can also try to run: Get-BitsTransfer -AllUsers | sort jobid | Format-List *"
        }

        "PXE"                                        = @{
            log = 'Distmgr', 'Smspxe', 'MP_ClientIDManager'
        }

        "ContentDistribution"                        = @{
            log = 'Distmgr'
        }

        "OSDeployment_clientPerspective"             = @{
            log = 'MP_ClientIDManager', 'Smsts', 'Execmgr'
        }

        "ClientInstallation"                         = @{
            log = 'Ccmsetup', 'Ccmsetup-ccmeval', 'CcmRepair', 'Client.msi', 'client.msi_uninstall'
        }

        "ClientPush"                                 = @{
            log = 'ccm'
        }

        "ApplicationMetering"                        = @{
            log = 'mtrmgr'
        }

        "Co-Management"                              = @{
            log       = 'CoManagementHandler', 'ComplRelayAgent'
            writeHost = "Check also Event Viewer: 'Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin' and 'Microsoft-Windows-AAD/Operational'"
        }

        "PolicyProcessing"                           = @{
            log = 'PolicyAgent', 'CcmMessaging'
        }

        "CMG"                                        = @{
            log          = 'CloudMgr', 'SMS_CLOUD_PROXYCONNECTOR', 'CMGService', 'CMGSetup', 'CMGContentService'
            writeWarning = "CMG* logs are stored on CMG machine and periodically downloaded to SCCM server. So there can be delay (approx. 10 minutes)."
        }

        "CMGDeployments"                             = @{
            log          = 'CloudMgr', 'CMGSetup'
            writeWarning = "CMG* logs are stored on CMG machine and periodically downloaded to SCCM server. So there can be delay (approx. 10 minutes)."
        }

        "CMGHealth"                                  = @{
            log          = 'CMGService', 'SMS_Cloud_ProxyConnector'
            writeWarning = "CMG* logs are stored on CMG machine and periodically downloaded to SCCM server. So there can be delay (approx. 10 minutes)."
        }

        "CMGClientTraffic"                           = @{
            log          = 'CMGHttpHandler', 'CMGService', 'SMS_Cloud_ProxyConnector'
            writeWarning = "CMG* logs are stored on CMG machine and periodically downloaded to SCCM server. So there can be delay (approx. 10 minutes)."
        }

        "Compliance"                                 = @{
            log = 'CIAgent', 'CITaskManager', 'DCMAgent', 'DCMReporting', 'DcmWmiProvider'
        }

        "Discovery"                                  = @{
            log = 'adsgdis', 'adsysdis', 'adusrdis', 'ADForestDisc', 'ddm', 'InventoryAgent', 'netdisc'
        }

        "Inventory"                                  = @{
            log = 'InventoryAgent'
        }

        "InventoryProcessing"                        = @{
            log = 'dataldr', 'invproc', 'sinvproc'
        }

        "WOL"                                        = @{
            log = 'Wolmgr', 'WolCmgr'
        }

        "NotificationServerInstall"                  = @{
            log = 'BgbSetup', 'bgbisapiMSI'
        }

        "NotificationServer"                         = @{
            log = 'bgbmgr', 'BGBServer', 'BgbHttpProxy'
        }

        "NotificationClient"                         = @{
            log = 'CcmNotificationAgent'
        }

        "BootImageUpdate"                            = @{
            log = 'dism'
        }

        "ApplicationManagement"                      = @{
            log = 'AppIntentEval', 'AppDiscovery', 'AppEnforce', 'AppGroupHandler', 'BusinessAppProcessWorker', 'Ccmsdkprovider', 'colleval', 'WsfbSyncWorker', 'NotiCtrl', 'PrestageContent', 'SettingsAgent', 'SMS_BUSINESS_APP_PROCESS_MANAGER', 'SMS_CLOUDCONNECTION', 'SMS_ImplicitUninstall', 'SMSdpmon', 'SoftwareCenterSystemTasks', 'TSDTHandler'
        }

        "PackagesAndPrograms"                        = @{
            log = 'colleval', 'execmgr'
        }

        "AssetIntelligence"                          = @{
            log = 'AssetAdvisor', 'aikbmgr', 'AIUpdateSvc', 'AIUSMSI', 'AIUSSetup', 'ManagedProvider', 'MVLSImport'
        }

        "BackupAndRecovery"                          = @{
            log = 'ConfigMgrSetup', 'Smsbkup', 'smssqlbkup', 'Smswriter'
        }

        "CertificateEnrollment"                      = @{
            log       = 'CertEnrollAgent', 'Crp', 'Crpctrl', 'Crpsetup', 'Crpmsi', 'NDESPlugin'
            writeHost = "You can also use the following log files:`nIIS log files for Network Device Enrollment Service: %SYSTEMDRIVE%\inetpub\logs\LogFiles\W3SVC1`nIIS log files for the certificate registration point: %SYSTEMDRIVE%\inetpub\logs\LogFiles\W3SVC1`nAnd mscep.log (This file is located in the folder for the NDES account profile, for example, in C:\Users\SCEPSvc)"
        }

        "ClientNotification"                         = @{
            log = 'bgbmgr', 'BGBServer', 'BgbSetup', 'bgbisapiMSI', 'BgbHttpProxy', 'CcmNotificationAgent'
        }

        "ComplianceSettingsAndCompanyResourceAccess" = @{
            log = 'CIAgent', 'CITaskManager', 'DCMAgent', 'DCMReporting', 'DcmWmiProvider'
        }

        "ConfigurationManagerConsole"                = @{
            log = 'ConfigMgrAdminUISetup', 'SmsAdminUI', 'Smsprov'
        }

        "ContentManagement"                          = @{
            log = 'CloudDP', 'CloudMgr', 'DataTransferService', 'PullDP', 'PrestageContent', 'PkgXferMgr', 'SMSdpmon', 'smsdpprov', 'smsdpusage'
        }

        "DesktopAnalytics"                           = @{
            log = 'M365ADeploymentPlanWorker', 'M365ADeviceHealthWorker', 'M365AHandler', 'M365AUploadWorker', 'SmsAdminUI'
        }

        "EndpointAnalytics"                          = @{
            log = 'UXAnalyticsUploadWorker', 'SensorWmiProvider', 'SensorEndpoint', 'SensorManagedProvider'
        }

        "EndpointProtection"                         = @{
            log = 'EndpointProtectionAgent', 'EPCtrlMgr', 'EPMgr', 'EPSetup'
        }

        "Extensions"                                 = @{
            log = 'AdminUI.ExtensionInstaller', 'FeatureExtensionInstaller', 'SmsAdminUI'
        }

        "Metering"                                   = @{
            log = 'mtrmgr', 'SWMTRReportGen', 'swmproc'
        }

        "Migration"                                  = @{
            log = 'migmctrl'
        }

        "MobileDevicesEnrollment"                    = @{
            log = 'DMPRP', 'dmpmsi', 'DMPSetup', 'enrollsrvMSI', 'enrollmentweb', 'enrollwebMSI', 'enrollmentservice', 'SMS_DM'
        }

        "ExchangeServerConnector"                    = @{
            log = 'easdisc'
        }

        "MobileDeviceLegacy"                         = @{
            log = 'DmCertEnroll', 'DMCertResp.htm', 'DmClientHealth', 'DmClientRegistration', 'DmClientSetup', 'DmClientXfer', 'DmCommonInstaller', 'DmInstaller', 'DmpDatastore', 'DmpDiscovery', 'DmpHardware', 'DmpIsapi', 'dmpmsi', 'DMPSetup', 'DmpSoftware', 'DmpStatus', 'DmSvc', 'FspIsapi'
        }

        "OSDeployment"                               = @{
            log = 'CAS', 'ccmsetup', 'CreateTSMedia', 'Dism', 'Distmgr', 'DriverCatalog', 'mcsisapi', 'mcsexec', 'mcsmgr', 'mcsprv', 'MCSSetup', 'MCSMSI', 'Mcsperf', 'MP_ClientIDManager', 'MP_DriverManager', 'OfflineServicingMgr', 'Setupact', 'Setupapi', 'Setuperr', 'smpisapi', 'Smpmgr', 'smpmsi', 'smpperf', 'smspxe', 'smssmpsetup', 'SMS_PhasedDeployment', 'Smsts', 'TSAgent', 'TaskSequenceProvider', 'loadstate', 'scanstate'
        }

        "PowerManagement"                            = @{
            log = 'pwrmgmt'
        }

        "RemoteControl"                              = @{
            log = 'CMRcViewer'
        }

        "Reporting"                                  = @{
            log = 'srsrp', 'srsrpMSI', 'srsrpsetup'
        }

        "Role-basedAdministration"                   = @{
            log = 'hman', 'SMSProv'
        }

        "SoftwareMetering"                           = @{
            log = 'mtrmgr'
        }

        "SoftwareUpdates"                            = @{
            log = 'AlternateHandler', 'ccmperf', 'DeltaDownload', 'PatchDownloader', 'PolicyEvaluator', 'RebootCoordinator', 'ScanAgent', 'SdmAgent', 'ServiceWindowManager', 'SMS_ISVUPDATES_SYNCAGENT', 'SMS_OrchestrationGroup', 'SmsWusHandler', 'StateMessage', 'SUPSetup', 'UpdatesDeployment', 'UpdatesHandler', 'UpdatesStore', 'WCM', 'WSUSCtrl', 'wsyncmgr', 'WUAHandler'
        }

        "WindowsServicing"                           = @{
            log = 'CBS', 'DISM', 'setupact'
        }

        "WindowsUpdateAgent"                         = @{
            log = 'WindowsUpdate'
        }

        "WSUSServer"                                 = @{
            log = 'Change', 'SoftwareDistribution'
        }
    }
    #endregion prepare

    #region open corresponding logs etc
    if ($area) {
        $result = $areaDetails.GetEnumerator() | ? Key -EQ $area | select -ExpandProperty Value

        if (!$result) { throw "Undefined area '$area'" }

        $logName = $result.log | Sort-Object
    } else {
        # user have used logName parameter
    }

    Write-Warning "Opening log(s): $($logName -join ', ')"

    # output logs description
    _getLogDescription $logName

    if ($result.writeHost) { Write-Host ("`n" + $result.writeHost + "`n") }
    if ($result.writeWarning) { Write-Warning $result.writeWarning }

    # open logs
    _openLog $logName
    #endregion open corresponding logs etc
}