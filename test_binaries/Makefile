CC=clang++
OPT=-O3 -march=native
BMARGS=-isystem benchmark/include -Lbenchmark/build/src -lbenchmark -lpthread -lbenchmark_main -lpfm
OTHER=-std=c++20

all: bitcoin_SwapBase64_aligned bitcoin_SwapBase64_unaligned

bitcoin_SwapBase64_aligned:
	$(CC) bitcoin_SwapBase64.cc $(OPT) $(BMARGS) $(OTHER) -mbranches-within-32B-boundaries -o bmprog_bitcoin_swapbase64_aligned

bitcoin_SwapBase64_unaligned:
	$(CC) bitcoin_SwapBase64.cc $(OPT) $(BMARGS) $(OTHER) -o bmprog_bitcoin_swapbase64_unaligned	

clean:
	rm -f bitcoin_SwapBase64_aligned
	rm -f bitcoin_SwapBase64_unaligned
	