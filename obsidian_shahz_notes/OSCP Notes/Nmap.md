```

──(root㉿kali)-[~]
	
	└─# nmap -p- -Pn 10.10.157.248 -v -T5 --min-rate 1500 --max-rtt-timeout 500ms --max-retries 3 --open -oN nmap_ports.txt
```
