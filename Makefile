ARTIFUCT = ./main
CC = gcc
CSRC = \
  ./main.c \
  ./tcp.c

$(ARTIFUCT): $(CSRC)

test: $(ARTIFUCT)
	$(ARTIFUCT)

clean:
	rm -f $(ARTIFUCT)
