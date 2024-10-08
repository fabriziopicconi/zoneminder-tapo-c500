# ZoneMinder for my Tapo C500 camera control script

A [ZoneMinder](https://zoneminder.com/) PTZ control script for the Tapo C500 camera.

Tested on:

- Ubuntu: 24.04 LTS server
- zoneminder: 1.36.33
- Tapo C500: 1.1.4

Thanks to [oparm](https://github.com/oparm) for solid background of this work

## Features
- Pan
- Tilt
- Zoom (through ZoneMinder)
- Sleep : Lens Mask On
- Wake : Lens Mask Off
- Up to 8 presets
- Reset (camera recalibrates and returns to its default position)
- Reboot

### Reset

The camera will recalibrate by panning and tilting itself.

### Reboot

It does indeed reboot the camera...

## Step 1 : Install the script on the system

This was tested on Ubuntu Server 20.04, just after installing ZoneMinder (following their wiki).

Install dependencies :

```
sudo apt install libjson-pp-perl libjson-parse-perl
```

On your system, copy the file named **TapoC200.pm** to **/usr/share/perl5/ZoneMinder/Control/** :

```
cd /usr/share/perl5/ZoneMinder/Control/
sudo wget https://github.com/fabriziopicconi/zoneminder-tapo-c500/raw/main/TapoC200.pm
sudo systemctl restart zoneminder
```

Make sure it has the same permissions as the existing control scripts in that directory :

<pre>
user@zmserver:/usr/share/perl5/ZoneMinder/Control# ls -alh
-rw-r--r-- 1 root   root    12K Feb 23  2023 3S.pm
-rw-r--r-- 1 root   root    16K Feb 23  2023 Amcrest_HTTP.pm
-rw-r--r-- 1 root   root    15K Feb 23  2023 AxisV2.pm
-rw-r--r-- 1 root   root    18K Feb 23  2023 Dahua.pm
-rw-r--r-- 1 root   root   4.8K Feb 23  2023 DCS3415.pm
-rw-r--r-- 1 root   root   7.2K Feb 23  2023 DCS5020L.pm
-rw-r--r-- 1 root   root    13K Feb 23  2023 DericamP2.pm
-rw-r--r-- 1 root   root    23K Feb 23  2023 FI8608W_Y2k.pm
-rw-r--r-- 1 root   root    26K Feb 23  2023 FI8620_Y2k.pm
-rw-r--r-- 1 root   root   6.2K Feb 23  2023 FI8908W.pm
-rw-r--r-- 1 root   root   7.6K Feb 23  2023 FI8918W.pm
-rw-r--r-- 1 root   root    22K Feb 23  2023 FI9821W_Y2k.pm
-rw-r--r-- 1 root   root    23K Feb 23  2023 FI9831W.pm
-rw-r--r-- 1 root   root   8.2K Feb 23  2023 Floureon.pm
-rw-r--r-- 1 root   root   8.7K Feb 23  2023 FoscamCGI.pm
-rw-r--r-- 1 root   root   9.5K Feb 23  2023 FOSCAMR2C.pm
-rw-r--r-- 1 root   root    12K Feb 23  2023 HikVision.pm
-rw-r--r-- 1 root   root   6.9K Feb 23  2023 IPCAMIOS.pm
-rw-r--r-- 1 root   root   8.1K Feb 23  2023 IPCC7210W.pm
-rw-r--r-- 1 root   root   6.9K Feb 23  2023 Keekoon.pm
-rw-r--r-- 1 root   root   9.6K Feb 23  2023 LoftekSentinel.pm
-rw-r--r-- 1 root   root    11K Feb 23  2023 M8640.pm
-rw-r--r-- 1 root   root   7.2K Feb 23  2023 MaginonIPC.pm
-rw-r--r-- 1 root   root   4.6K Feb 23  2023 mjpgStreamer.pm
-rw-r--r-- 1 root   root   4.6K Feb 23  2023 Ncs370.pm
-rw-r--r-- 1 root   root    28K Feb 23  2023 Netcat.pm
-rw-r--r-- 1 root   root    25K Feb 23  2023 onvif.pm
-rw-r--r-- 1 root   root   6.6K Feb 23  2023 PanasonicIP.pm
-rw-r--r-- 1 root   root    18K Feb 23  2023 PelcoD.pm
-rw-r--r-- 1 root   root    19K Feb 23  2023 PelcoP.pm
-rw-r--r-- 1 root   root   9.7K Feb 23  2023 PSIA.pm
-rw-r--r-- 1 root   root    39K Feb 23  2023 Reolink.pm
-rw-r--r-- 1 root   root   6.4K Feb 23  2023 SkyIPCam7xx.pm
-rw-r--r-- 1 root   root   8.2K Feb 23  2023 Sony.pm
-rw-r--r-- 1 root   root   7.7K Feb 23  2023 SPP1802SWPTZ.pm
<b>-rw-r--r-- 1 root   root    14K Aug  6 17:56 TapoC200.pm</b>
-rw-r--r-- 1 root   root   5.2K Feb 23  2023 Toshiba_IK_WB11A.pm
-rw-r--r-- 1 root   root    12K Feb 23  2023 Trendnet.pm
-rw-r--r-- 1 root   root    20K Feb 23  2023 Visca.pm
-rw-r--r-- 1 root   root   4.6K Feb 23  2023 Vivotek_ePTZ.pm
-rw-r--r-- 1 root   root   8.9K Feb 23  2023 WanscamHW0025.pm
-rw-r--r-- 1 root   root    13K Feb 23  2023 Wanscam.pm
</pre>

## Step 2 : Add the control script to ZoneMinder

Use the same configuration when testing, unless stated otherwise.

In ZoneMinder "Console" Tab, click "Add" to add a new camera.

Go to "Control" tab and click on "Edit" next to "Control Type".

![tapoc200-monitor-control-tab-dummy](https://user-images.githubusercontent.com/83918778/120376401-24460000-c31c-11eb-90d2-7b84f14a5dc4.jpg)

Click on "Add New Control" :

![tapoc200-monitor-control-capabilities-tab-before](https://user-images.githubusercontent.com/83918778/120373376-9288c380-c318-11eb-9868-240a045a6a69.jpg)

Now fill each tab as shown in the following captures.

### Control capability main tab

Use the same settings as :

![tapoc200-monitor-control-capability-main-tab](https://user-images.githubusercontent.com/83918778/117584549-e2a3aa00-b10d-11eb-9db6-cb4095afcc2d.jpg)

### Control capability move tab

Use the same settings as :

![tapoc200-monitor-control-capability-move-tab](https://user-images.githubusercontent.com/83918778/117584552-e8998b00-b10d-11eb-9c2c-36503ea496d6.jpg)

### Control capability pan tab

Use the same settings as :

![tapoc200-monitor-control-capability-pan-tab](https://user-images.githubusercontent.com/83918778/117584555-edf6d580-b10d-11eb-9d69-c60ca8c8f786.jpg)

### Control capability tilt tab

Use the same settings as :

![tapoc200-monitor-control-capability-tilt-tab](https://user-images.githubusercontent.com/83918778/117584561-f3542000-b10d-11eb-98ff-38b53cc5a98c.jpg)

### Control capability presets tab

Use the same settings as :

![tapoc200-monitor-control-capability-presets-tab](https://user-images.githubusercontent.com/83918778/117584565-f7803d80-b10d-11eb-8752-9f24c744ce74.jpg)

**Now click on "Save" to save the new control.**

## Step 3 : Add the new monitor to ZoneMinder

**Important** : Click on cancel in the previously opened window (the Monitor one), and in ZoneMinder "Console" Tab, click again on "Add" to add a new camera.
This is needed to refresh the "Control Type" dropdown list with the new control we just added.

### Monitor source tab

![tapoc200-monitor-source-tab](https://user-images.githubusercontent.com/83918778/117584518-c6077200-b10d-11eb-86fa-7aba61aa6eca.jpg)

**Source Path** is the RTSP path used to display the stream inside ZoneMinder, it has nothing to do with the control script.
Inside the mobile application, create an account linked to the camera and use those credentials in the "Source Path".

Change user, password and IP. Leave the port to 554 and /stream1.

### Monitor control tab

![tapoc200-monitor-control-tab](https://user-images.githubusercontent.com/83918778/117584528-cbfd5300-b10d-11eb-85be-8ce2536e8d0b.jpg)

**Control Address** is the HTTPS path used to control the camera inside ZoneMinder.

Change admin_password to the password you created when you installed the mobile application (the password linked to your email address).

Change the IP address. **Leave the username to "admin"**, and the port to 443.

**Control Type** : Select "Tapo C200" inside the dropdown list.

**Now click on "Save" to save the new monitor.**

If everything went smoothly, you should now be able to control the camera.

## Check that the script is running

You can see the script's output in two ways :

1. Inside ZoneMinder in the by clicking on "Log" in the main menu
2. Or directly inside **/var/log/zm/zmcontrol_*.log**, here is how it should looks like :

```
...
05/09/2021 20:08:43.224080 zmcontrol_1[18057].INF [main:134] [Starting control server 1/TapoC200]
05/09/2021 20:08:43.264927 zmcontrol_1[18057].INF [main:141] [Control server 1/TapoC200 starting at 21/05/09 20:08:43]
05/09/2021 20:08:43.401039 zmcontrol_1[18057].INF [ZoneMinder::Control::TapoC200:165] [Token retrieved for https://192.168.1.1:443]
05/09/2021 20:08:43.406488 zmcontrol_1[18057].INF [ZoneMinder::Control::TapoC200:109] [Tapo C200 Controller opened]
...
```

## How to edit & troubleshoot the script

If you need to troubleshoot more deeply, enable the script debugging :

```
...
my $tapo_c200_debug = 1;
...
```

Reload the script by clicking "Save" in any window shown on the screenshots.

**Now you can reload the script easily by clicking the "Reset" buttons inside ZoneMinder.**

When the variable is set to 1, the "Reset" button in ZoneMinder will reload the script instead of calibrating the camera position.
This allows you to edit the script file and click on "Reset" so that your modifications are taken into account by ZoneMinder.

When you are done set that variable back to 0.

```
...
my $tapo_c200_debug = 0;
...
```

## Pan and tilt stepping

Set this variable to either 5/10/15. Those are the steps used by the mobile application, so they are supposed safe.

```
...
my $step = 15;
...
```

## Useful links and thanks to :

https://github.com/JurajNyiri/pytapo

https://github.com/oparm/zoneminder-tapo-c200
