To run: 

Use the Makefile to compile all  the code

Begin by starting the servers:
1. ./pke_server
2. ./tfa_server <IP Address that the servers are running on>
3. ./lodi_server <IP Address>

Register with the lodi_client:
4. ./lodi_client <ServerIP> <UserID> register

Then run the TFA client with the same ID:
5. ./tfa_client <ServerIP> <UserID> 

Now login with the logi_client:
6. ./lodi_client <ServerIP> <UserID> login

You should then be prompted on tfa_client to confirm the login (the request will timeout after 10 seconds) 
Select yes/no on tfa_client to confirm or deny login request

