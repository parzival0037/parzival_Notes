nxc is dependant on impacket lib when you use impacket-GetNPUsers.py
Hence, update impacket-> using pipx
pipx show impacket


This is the error I got:
```
┌──(root㉿kali)-[~]
└─# nxc smb 10.67.139.231 -u '' -p '' --shares
Traceback (most recent call last):
  File "/usr/bin/nxc", line 8, in <module>
    sys.exit(main())
             ~~~~^^
  File "/usr/lib/python3/dist-packages/nxc/netexec.py", line 143, in main
    protocol_object = getattr(p_loader.load_protocol(protocol_path), args.protocol)
                              ~~~~~~~~~~~~~~~~~~~~~~^^^^^^^^^^^^^^^
  File "/usr/lib/python3/dist-packages/nxc/loaders/protocolloader.py", line 16, in load_protocol
    loader.exec_module(protocol)
    ~~~~~~~~~~~~~~~~~~^^^^^^^^^^
  File "<frozen importlib._bootstrap_external>", line 1027, in exec_module
  File "<frozen importlib._bootstrap>", line 488, in _call_with_frames_removed
  File "/usr/lib/python3/dist-packages/nxc/protocols/smb.py", line 33, in <module>
    from nxc.connection import connection, sem, requires_admin, dcom_FirewallChecker
  File "/usr/lib/python3/dist-packages/nxc/connection.py", line 15, in <module>
    from nxc.protocols.ldap.laps import laps_search
  File "/usr/lib/python3/dist-packages/nxc/protocols/ldap/laps.py", line 9, in <module>
    from impacket.dcerpc.v5.gkdi import MSRPC_UUID_GKDI, GkdiGetKey, GroupKeyEnvelope
ModuleNotFoundError: No module named 'impacket.dcerpc.v5.gkdi'

┌──(root㉿kali)-[~]
└─# python3 -c "from impacket.dcerpc.v5 import gkdi; print('Module found!')"                                
-bash: !': event not found
```






`pipx install nxc

**Step 1**: Remove old or broken Impacket installation

Since your system might have an old version of Impacket installed that doesn't have the required gkdi module, first remove the old version:

`sudo apt remove python3-impacket impacket -y
`pip3 uninstall impacket -y

// TO remove impacket
`pip3 uninstall impacket --break-system-packages -y  

**Step 2**: Install Impacket via pipx (or pip if preferred)
Option 1: Using pipx (recommended for better isolation)

If you don't have pipx installed, first install it:

`sudo apt install pipx -y
`pipx ensurepath

Then restart your terminal session or run:

`source ~/.bashrc`
Then, install Impacket via pipx:

`pipx install impacket`

Option 2: Using pip (if you don't want to use pipx)
`pip3 install --upgrade impacket`


To check if impacket is installed and working or not try:
`┌──(root㉿kali)-[~]
`└─# python3 -c "from impacket.dcerpc.v5 import gkdi; print('Module found')"
`Module found`



After the nxc is installed

┌──(root㉿kali)-[~]
└─# rm -f /root/.nxc/workspaces/default/smb.db

