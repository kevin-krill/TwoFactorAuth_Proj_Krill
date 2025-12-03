To run: 

Use the Makefile to compile all the code
If running on GCP make sure all the servers run on the same instance

Begin by starting the servers:
1. ./pke_server
2. ./tfa_server <IP Address that the servers are running on>
3. ./lodi_server <IP Address>

***********Repeat Process for each new user**************
Register with the lodi_client:
4. ./lodi_client <ServerIP> <UserID#> 
    you will then be prompted login / register
    input register

Then run the TFA client with the same ID:
5. ./tfa_client <ServerIP> <UserID#> 

Now login with the logi_client:
6. ./lodi_client <ServerIP> <UserID#>
    you will be prompted login / register
    input login

7. You should then be prompted on tfa_client to confirm the login (the request will timeout after 10 seconds) 
Select yes/no on tfa_client to confirm or deny login request

**********************************************************


Once logged in you will now have access to all the features.
The console will prompt you 1-5 to select what to do. Follow the prompts for further directions.



