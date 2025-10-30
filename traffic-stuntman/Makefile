TARGET=traffic-stuntman
IFACE=lo

.PHONY: all clean 

build:
	go generate	&& go build

all:
	go generate	&& go build
	sudo ./traffic-stuntman $(IFACE)

clean:
	rm -f *bpfeb*
	rm -f *bpfel*
	rm -f $(TARGET)