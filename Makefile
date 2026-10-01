all: rfmp_c

rfmp_c: hamza_client.c
	gcc -o rfmp_c hamza_client.c

clean:
	rm -f rfmp_c
