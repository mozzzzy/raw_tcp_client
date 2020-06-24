ARTIFUCT = ./main
CC = gcc
CSRC = \
  ./main.c \
  ./hextet/hextet.c \
  ./tcp_header/tcp_header.c \
  ./ipv4_header/ipv4_header.c \
  ./tcp_packet/tcp_packet.c

$(ARTIFUCT): $(CSRC)

test: $(ARTIFUCT)
	$(ARTIFUCT)

clean:
	rm -f $(ARTIFUCT)
