all: tlsproxy

tlsproxy: *.c
	$(CC) -o $@ -Iinclude -I. $^

clean:
	rm -f tlsproxy
