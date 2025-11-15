CC = wcl
CFLAGS = -ms -ox -zq -i=include -i=../common/include -i=$(%WATCOM)/h -i=$(%WATCOM)/h/dos -i=$(%WATCOM)/h/nt

TARGET = build/DOSSRV.EXE
SRCS = src/main.c src/serial.c ../common/src/rle.c

all: $(TARGET)

$(TARGET): $(SRCS)
	@mkdir -p build
	$(CC) $(CFLAGS) -fe=$(TARGET) $(SRCS)

clean:
	rm -f *.obj src/*.obj
	rm -f $(TARGET)
