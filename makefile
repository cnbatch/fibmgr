CXXFLAGS = -Wall -O3 -std=c++20
INCLUDEDIR = -I./ -I/usr/include/ -I/usr/local/include/
LDFLAGS = -L/usr/lib -L/usr/local/lib
OUTPUT = fibmgr
SOURCES = main.cpp fibmgr.cpp
OBJECTS=${SOURCES:.cpp=.o}

all : ${OUTPUT}

install:
	@cp ${OUTPUT} /usr/local/bin

uninstall:
	@rm /usr/local/bin/${OUTPUT}

clean:
	@rm -f ${OUTPUT} *.o *~

${OUTPUT}: ${OBJECTS}
	@c++ ${LDFLAGS} ${LDLIBS} ${OBJECTS} -o ${OUTPUT}

.cpp.o:
	@c++ ${INCLUDEDIR} ${CXXFLAGS} -c ${.IMPSRC} -o ${.TARGET}

