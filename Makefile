build: dnsclient

dnsclient: dnsclient.c
	gcc dnsclient.c -o dnsclient

run:
	./dnsclient yahoo.com MX

clean:
	rm *.log dnsclient 
