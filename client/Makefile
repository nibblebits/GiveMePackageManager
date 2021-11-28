OBJECTS=../shared/build/libgivemeshared.a
INCLUDES= -I./ -I ../shared
ADDITIONAL_FLAGS= -g

all: ${OBJECTS}
	gcc ${INCLUDES} ./main.c ${OBJECTS} ${ADDITIONAL_FLAGS} -lcrypto -lzip -o ./giveme 

clean:
	rm -rf ${OBJECTS}