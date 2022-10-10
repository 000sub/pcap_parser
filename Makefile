TARGET	=	main
CC	=	gcc
OBJECTS = main.o

all	:	$(TARGET)

$(TARGET)	:	$(OBJECTS)
	$(CC)	-o	$@	$^

clean	:
	rm	*.o	main

