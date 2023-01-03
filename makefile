
all:
	clang main.c ./utils/re_elf.c ./utils/re_rebuild.c -o ./output/rebuid-elf-section

clean:
	rm -r arm64-v8a
	rm -r armeabi-v7a