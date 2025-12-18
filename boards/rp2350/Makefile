platform = raspberrypi
board = pico
framework = arduino

help:  ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | \
	awk 'BEGIN {FS = ":.*##"}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

bld_clang_db: ## Build clangd commands that use the arm-none-eabi toolchain
	pio run -t compiledb

inst_arduino_plat: ## Install the platform specefied, through platformio
	pio pkg install -p atmelsam

update: ## Update all packages in this project
	pio pkg update

VLV ?= 
compile: $1 ## Compile the files into a board flashable image
	pio run $(VLV)

upload: ## Compile and upload the image to the board
	pio run -t upload

monitor: ## Begin serial communication with the device
	pio device monitor

up_monitor: ## Compile, upload and begin serial comunication with the device
	pio run -t upload -t monitor

clean:
	pio run -t clean
