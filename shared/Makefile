OBJECTS=./build/log.o ./build/af_unix_network.o ./build/network.o ./build/blockchain.o ./build/package.o ./build/sha256.o ./build/tpool.o ./build/key.o ./build/misc.o ./build/vector.o
INCLUDES= -I ./
ADDITIONAL_FLAGS= -g
all: ${OBJECTS}
	ar -rc ./build/libgivemeshared.a ${OBJECTS}

./build/log.o:./log.c
	gcc ${INCLUDES} ./log.c -c ${ADDITIONAL_FLAGS} -o ./build/log.o 

./build/sha256.o:./sha256.c
	gcc ${INCLUDES} ./sha256.c -c ${ADDITIONAL_FLAGS} -o ./build/sha256.o 

./build/package.o:./package.c
	gcc ${INCLUDES} ./package.c -c ${ADDITIONAL_FLAGS} -o ./build/package.o 

./build/af_unix_network.o:./af_unix_network.c
	gcc ${INCLUDES} ./af_unix_network.c -c ${ADDITIONAL_FLAGS} -o ./build/af_unix_network.o 

./build/network.o:./network.c
	gcc ${INCLUDES} ./network.c -c ${ADDITIONAL_FLAGS} -o ./build/network.o 


./build/blockchain.o:./blockchain.c
	gcc ${INCLUDES} ./blockchain.c -c ${ADDITIONAL_FLAGS} -o ./build/blockchain.o 


./build/tpool.o:./tpool.c
	gcc ${INCLUDES} ./tpool.c -c ${ADDITIONAL_FLAGS} -o ./build/tpool.o 

./build/key.o:./key.c
	gcc ${INCLUDES} ./key.c -c ${ADDITIONAL_FLAGS} -o ./build/key.o 

./build/misc.o:./misc.c
	gcc ${INCLUDES} ./misc.c -c ${ADDITIONAL_FLAGS} -o ./build/misc.o 

./build/vector.o:./vector.c
	gcc ${INCLUDES} ./vector.c -c ${ADDITIONAL_FLAGS} -o ./build/vector.o 


clean:
	rm -rf ${OBJECTS}