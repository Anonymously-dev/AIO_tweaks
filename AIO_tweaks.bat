:: Disables User Account Control Temporarily - Without this entry, some commands in the currentuser.cmd script will fail. UAC is re-enabled in the currentuser.cmd script again.
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f
REG ADD "HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f
:: Disable Windows Spotlight and set the normal Windows Picture as the desktop background
:: Disable Windows Spotlight on the lock screen
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnLockScreen /t REG_DWORD /d 1 /f
:: Disable Windows Spotlight suggestions, tips, tricks, and more on the lock screen
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 0 /f
:: Disable Windows Spotlight on Settings
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightActiveUser /t REG_DWORD /d 1 /f
:: Set desktop background to a normal Windows picture
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v Wallpaper /t REG_SZ /d "C:\Windows\Web\Wallpaper\Windows\img19.jpg" /f
:: Ensure the wallpaper style is set to fill (2 is for fill, 10 is for fit)
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v WallpaperStyle /t REG_SZ /d "2" /f

:: Prevents Dev Home Installation
reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\DevHomeUpdate" /f

:: Prevents New Outlook for Windows Installation
reg.exe delete "HKLM\SOFTWARE\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate" /f

:: Prevents Chat Auto Installation and Removes Chat Icon
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" /v "ChatIcon" /t REG_DWORD /d 3 /f

:: Start Menu Customization
reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v ConfigureStartPins /t REG_SZ /d "{ \"pinnedList\": [] }" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v ConfigureStartPins_ProviderSet /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\current\device\Start" /v ConfigureStartPins_WinningProvider /t REG_SZ /d B5292708-1619-419B-9923-E5D9F3925E71 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start" /v ConfigureStartPins /t REG_SZ /d "{ \"pinnedList\": [] }" /f
reg.exe add "HKLM\SOFTWARE\Microsoft\PolicyManager\providers\B5292708-1619-419B-9923-E5D9F3925E71\default\Device\Start" /v ConfigureStartPins_LastWrite /t REG_DWORD /d 1 /f

:: Disables News and Interests
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f

:: Disables Windows Consumer Features Like App Promotions etc.
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f

:: Disables Bitlocker Auto Encryption on Windows 11 24H2 and Onwards
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v TCGSecurityActivationDisabled /t REG_DWORD /d 1 /f

:: Disables Cortana
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f

:: Disables Activity History
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableActivityFeed /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v PublishUserActivities /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v UploadUserActivities /t REG_DWORD /d 0 /f

:: Disables Location Tracking
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v Value /t REG_SZ /d Deny /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v SensorPermissionState /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v Status /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SYSTEM\Maps" /v AutoUpdateEnabled /t REG_DWORD /d 0 /f

:: Disables Telemetry
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v AllowTelemetry /t REG_DWORD /d 0 /f

:: Disables Windows Ink Workspace
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v AllowWindowsInkWorkspace /t REG_DWORD /d 0 /f

:: Disables Feedback Notifications
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f

:: Disables the Advertising ID for All Users
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v DisabledByGroupPolicy /t REG_DWORD /d 1 /f

:: Disables Windows Error Reporting
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f

:: Disables Delivery Optimization
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v DODownloadMode /t REG_DWORD /d 0 /f

:: Disables Remote Assistance
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v fAllowToGetHelp /t REG_DWORD /d 0 /f

:: Search Windows Update for Drivers First
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v SearchOrderConfig /t REG_DWORD /d 1 /f

:: Gives Multimedia Applications like Games and Video Editing a Higher Priority
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v SystemResponsiveness /t REG_DWORD /d 0 /f
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile" /v NetworkThrottlingIndex /t REG_DWORD /d 10 /f

:: Controls whether the memory page file is cleared at shutdown. Value 0 means it will not be cleared, speeding up shutdown.
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v ClearPageFileAtShutdown /t REG_DWORD /d 0 /f

:: Enables NDU (Network Diagnostic Usage) Service on Startup
reg.exe add "HKLM\SYSTEM\ControlSet001\Services\Ndu" /v Start /t REG_DWORD /d 2 /f

:: Increases IRP stack size to 30 for the LanmanServer service to Improve Network Performance and Stability
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v IRPStackSize /t REG_DWORD /d 30 /f

:: Hides the Meet Now Button on the Taskbar
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

:: Gives Graphics Cards a Higher Priority for Gaming
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "GPU Priority" /t REG_DWORD /d 8 /f

:: Gives the CPU a Higher Priority for Gaming
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v Priority /t REG_DWORD /d 6 /f

:: Gives Games a higher priority in the system's scheduling
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Multimedia\SystemProfile\Tasks\Games" /v "Scheduling Category" /t REG_SZ /d "High" /f


:: Disables Storage Sense
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v 01 /t REG_DWORD /d 0 /f

:: Disable Xbox GameDVR
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f

:: Disable Tablet Mode
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v TabletMode /t REG_DWORD /d 0 /f



:: Disables OneDrive Automatic Backups of Important Folders (Documents, Pictures etc.)
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\OneDrive" /v KFMBlockOptIn /t REG_DWORD /d 1 /f
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v DisableFileSyncNGSC /t REG_DWORD /d 1 /f

:: Disables the "Push To Install" feature in Windows
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v "DisablePushToInstall" /t REG_DWORD /d 1 /f

:: Disables Consumer Account State Content
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableConsumerAccountStateContent" /t REG_DWORD /d 1 /f

:: Disables Cloud Optimized Content
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v "DisableCloudOptimizedContent" /t REG_DWORD /d 1 /f


:: DELETES SCHEDULED TASKS REGISTRY KEYS
:: Deleting Application Compatibility Appraiser
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0600DD45-FAF2-4131-A006-0B17509B9F78}" /f
:: Deleting Customer Experience Improvement Program
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{4738DE7A-BCC1-4E2D-B1B0-CADB044BFA81}" /f
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{6FAC31FA-4A85-4E64-BFD5-2154FF4594B3}" /f
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{FC931F16-B50A-472E-B061-B6F79A71EF59}" /f
:: Deleting Program Data Updater
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{0671EB05-7D95-4153-A32B-1426B9FE61DB}" /f

:: Deleting QueueReporting
reg.exe delete "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{E3176A65-4E44-4ED3-AA73-3283660ACB9C}" /f

:: AMD Fastboot Fix
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\usbflags\18D1D00D0100" /v "osvc" /t REG_BINARY /d "0000" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\usbflags\18D1D00D0100" /v "SkipContainerIdQuery" /t REG_BINARY /d "01000000" /f
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\usbflags\18D1D00D0100" /v "SkipBOSDescriptorQuery" /t REG_BINARY /d "01000000" /f
:: Disable Bing Search
reg.exe add "HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
:: Disable Aboslute bluetooth Vol
reg.exe add "HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Control\Bluetooth\Audio\AVRCP\CT" /v DisableAbsoluteVolume /t REG_DWORD /d 1 /f
:: JPEG Quality
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f


:: Disable Windows Spotlight on the lock screen
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightOnLockScreen /t REG_DWORD /d 1 /f
:: Disable Windows Spotlight suggestions, tips, tricks, and more on the lock screen
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 0 /f
:: Disable Windows Spotlight on Settings
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightActiveUser /t REG_DWORD /d 1 /f

reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackDocs /t REG_DWORD /d 1 /f
:: Disable AppDiagnostic
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f

reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
:: Not Reported
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f

reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "400" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f
:: Restore Windows Photo Viewer
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.bmp" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.cr2" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.dib" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.gif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.ico" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jfif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpe" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpeg" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpg" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jxr" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.png" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.tif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.tiff" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.wdp" /ve /d "PhotoViewer.FileAssoc.Tiff" /f

:: Disabling the Delivery of Personalized or Suggested Content Like App Suggestions, Tips, and Advertisements in Windows
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "FeatureManagementEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OEMPreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353694Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v TailoredExperiencesWithDiagnosticDataEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v IsMiEnabled /t REG_DWORD /d 0 /f
reg.exe delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\Subscriptions" /f
reg.exe delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy" /v "HasAccepted" /t REG_DWORD /d 0 /f
:: Removes OneDrive
reg.exe delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v OneDriveSetup /f

:: Align the taskbar to the left on Windows 11
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f

:: Hides and Removes News and Interests from PC and Taskbar
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsTaskbarViewMode /t REG_DWORD /d 2 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feeds" /v ShellFeedsEnabled /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" /v EnableFeeds /t REG_DWORD /d 0 /f
:: Disables Location Services
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v LocationServicesEnabled /t REG_DWORD /d 0 /f

:: Disables Input Personalization Settings
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Personalization\Settings" /v AcceptedPrivacyPolicy /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitTextCollection /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\InputPersonalization" /v RestrictImplicitInkCollection /t REG_DWORD /d 1 /f

:: Disables Automatic Feedback Sampling
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v AutoSample /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Feedback" /v ServiceEnabled /t REG_DWORD /d 0 /f


:: Disable "Let websites provide locally relevant content by accessing my language list"
reg.exe add "HKEY_CURRENT_USER\Control Panel\International\User Profile" /v HttpAcceptLanguageOptOut /t REG_DWORD /d 1 /f

:: Disables "Let Windows track app launches to improve Start and search results"
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v Start_TrackProgs /t REG_DWORD /d 1 /f

:: Disables Background Apps
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v GlobalUserDisabled /t REG_DWORD /d 1 /f

:: Disables App Diagnostics
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AppDiagnostics" /v AppDiagnosticsEnabled /t REG_DWORD /d 0 /f

:: Disables Delivery Optimization
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization" /v DODownloadMode /t REG_DWORD /d 0 /f

:: Disables Tablet Mode
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\ImmersiveShell" /v TabletMode /t REG_DWORD /d 0 /f

:: Disables Maps Auto Download
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Maps" /v AutoDownload /t REG_DWORD /d 0 /f

:: Disables Telemetry and Ads
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v NumberOfSIUFInPeriod /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableTailoredExperiencesWithDiagnosticData /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowSyncProviderNotifications /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d 0 /f
:: Manages and displays the status of ongoing operations, such as file copy, move, delete, etc.
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" /v EnthusiastMode /t REG_DWORD /d 1 /f

:: Set File Explorer to Open This PC instead of Quick Access
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v LaunchTo /t REG_DWORD /d 1 /f

:: Set Display for Performance
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v MenuShowDelay /t REG_DWORD /d 1 /f

:: On Shutdown, Windows will automatically close any running applications
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v AutoEndTasks /t REG_DWORD /d 1 /f

:: Sets the Mouse hover time to 400 milliseconds
reg.exe add "HKEY_CURRENT_USER\Control Panel\Mouse" /v MouseHoverTime /t REG_SZ /d "400" /f

:: Hides the Meet Now Button on the Taskbar
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v HideSCAMeetNow /t REG_DWORD /d 1 /f

:: Set Registry Keys to Enable End Task With Right Click
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarDeveloperSettings /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarEndTask /t REG_DWORD /d 1 /f
:: Disable Xbox GameDVR
reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_FSEBehavior /t REG_DWORD /d 2 /f
reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_Enabled /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_DXGIHonorFSEWindowsCompatible /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_HonorUserFSEBehaviorMode /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\System\GameConfigStore" /v GameDVR_EFSEFeatureFlags /t REG_DWORD /d 0 /f

:: Disables Bing Search in Start Menu
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f
:: Enables Show File Extensions
reg.exe add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v HideFileExt /t REG_DWORD /d 0 /f

:: Enables Dark Mode
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v AppsUseLightTheme /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v ColorPrevalence /t REG_DWORD /d 0 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v EnableTransparency /t REG_DWORD /d 1 /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v SystemUsesLightTheme /t REG_DWORD /d 0 /f

:: Set Desktop Background Dark Mode Wallpaper
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d "C:\Windows\Web\Wallpaper\Windows\img19.jpg" /f
:: Don't Update Last Access Time Stamp - This Can Improve File System Performance
fsutil.exe behavior set disableLastAccess 1

:: Restore Windows Photo Viewer and Set as Default Program for Image Files
:: Restore Windows Photo Viewer
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.bmp" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.cr2" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.dib" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.gif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.ico" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jfif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpe" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpeg" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jpg" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.jxr" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.png" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.tif" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.tiff" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Classes\.wdp" /ve /d "PhotoViewer.FileAssoc.Tiff" /f
:: Create Relevant File Associations
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.bmp\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.cr2\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.dib\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.gif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.ico\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jfif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpe\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpeg\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jpg\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.jxr\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.png\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tif\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.tiff\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
reg.exe add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.wdp\OpenWithProgids" /v "PhotoViewer.FileAssoc.Tiff" /t REG_NONE /f
:: Disables Wallpaper JPEG Quality Reduction in Windows 10 
reg.exe add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "JPEGImportQuality" /t REG_DWORD /d 100 /f

:: Disables User Account Control Temporarily - Without this entry, some commands in the currentuser.cmd script will fail. UAC is re-enabled in the currentuser.cmd script again.
reg.exe add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
::Services settings::
powershell.exe set-executionpolicy remotesigned
powershell.exe Set-Service -Name 'DiagTrack' -StartupType Disabled -ErrorAction Continue
powershell.exe Set-Service -Name 'diagsvc' -StartupType Disabled -ErrorAction Continue
powershell.exe Set-Service -Name 'DPS' -StartupType Disabled -ErrorAction Continue
powershell.exe Set-Service -Name 'WdiServiceHost' -StartupType Manual -ErrorAction Continue
powershell.exe Set-Service -Name 'WdiSystemHost' -StartupType Manual -ErrorAction Continue
powershell.exe Set-Service -Name 'MapsBroker' -StartupType Disabled -ErrorAction Continue
powershell.exe Set-Service -Name 'WerSvc' -StartupType Disabled -ErrorAction Continue



:: Restart PC to Apply All Changes
shutdown /r -t 1

