CC = gcc
CFLAGS = -Wall

TARGETS = pke_server tfa_server lodi_server tfa_client lodi_client

all: $(TARGETS)

pke_server: pke_server.c
	$(CC) $(CFLAGS) -o pke_server pke_server.c

tfa_server: tfa_server.c
	$(CC) $(CFLAGS) -o tfa_server tfa_server.c

lodi_server: lodi_server.c
	$(CC) $(CFLAGS) -o lodi_server lodi_server.c

tfa_client: tfa_client.c
	$(CC) $(CFLAGS) -o tfa_client tfa_client.c

lodi_client: lodi_client.c
	$(CC) $(CFLAGS) -o lodi_client lodi_client.c

clean:
	rm -f $(TARGETS)
