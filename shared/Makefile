OBJECTS=./build/log.o ./build/network.o ./build/package.o
INCLUDES= -I ./
ADDITIONAL_FLAGS= -g
all: ${OBJECTS}
	ar -rc ./build/libgivemeshared.a ${OBJECTS}

./build/log.o:./log.c
	gcc ${INCLUDES} ./log.c -c ${ADDITIONAL_FLAGS} -o ./build/log.o 

./build/package.o:./package.c
	gcc ${INCLUDES} ./package.c -c ${ADDITIONAL_FLAGS} -o ./build/package.o 

./build/network.o:./network.c
	gcc ${INCLUDES} ./network.c -c ${ADDITIONAL_FLAGS} -o ./build/network.o 


clean:
	rm -rf ${OBJECTS}