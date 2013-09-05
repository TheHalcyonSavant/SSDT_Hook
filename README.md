WinXP SSDT hook driver
====================
This is a device driver used for hiding files from the system by its filename. The output object file *SSDT_hook.sys* from this project is used by FileHide.exe (see [FileHide](../../../FileHide) for more details).  

*This project is part of my thesis defense done in 2010 at Technical University of Sofia(Bulgaria) during my graduation in Faculty of Computer Science and Control (FKSU)*

System Requirements
-----------------------------
WindowsNT 5.1-5.3 (XP Service Pack 1,2,3)

Compiling and Linking
-----------------------------
First you must install [WDK 7600](http://www.microsoft.com/en-us/download/details.aspx?id=11800);  
1). Open *Windows XP*/**x86 Checked Build Environment** from Start Menu;  
2). Locate *SSDT_hook* directory in the command prompt;  
3). Execute **build /cZwbg**
Now the driver *objchk_wxp_x86\i386\SSDT_hook.sys* is ready to be installed and used by FileHIde.
