all:
	cd ./shared && $(MAKE) all
	cd ./client && $(MAKE) all
	cd ./server && $(MAKE) all

clean:
	cd ./shared && $(MAKE) clean
	cd ./client && $(MAKE) clean
	cd ./server && $(MAKE) clean
