/*
    libpftw — parallel file tree walk library
    
    Copyright (C) 2015 Dmitry Yu Okunev <dyokunev@ut.mephi.ru> 0x8E30679C
    
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
    
    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    
    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <string.h>

#include "pftw.h"


int cb_print_pftw(
	const char *fpath,
	const struct stat *sb,
	int typeflag,
	struct FTW *ftwbuf,
	void *arg)
{
	return cb_print_ftw(fpath, sb, typeflag, ftwbuf);
}

int cb_print_ftw(
	const char *fpath,
	const struct stat *sb,
	int typeflag,
	struct FTW *ftwbuf)
{
	printf("%s\n", fpath);

	return FTW_CONTINUE;
}

int syntax(char *argv[]) {
	fprintf(stderr, "syntax: %s <pftw|nftw> <directory>\n", argv[0]);
	return -1;
}

int main(int argc, char *argv[]) {
	if (argc < 3)
		return syntax(argv);

	if (!strcmp(argv[1], "pftw")) {
		fprintf(stderr, "pftw_init(8) -> %i\n", pftw_init(8));
		fprintf(stderr, "pftw() -> %i\n", pftw(argv[2], cb_print_pftw, 0, FTW_PHYS|FTW_ACTIONRETVAL, NULL));
		fprintf(stderr, "pftw_deinit() -> %i\n", pftw_deinit());
		return 0;
	} else
	if (!strcmp(argv[1], "nftw")) {
		fprintf(stderr, "nftw() -> %i\n", nftw(argv[2], cb_print_ftw, 0, FTW_PHYS|FTW_ACTIONRETVAL));
		return 0;
	}

	return syntax(argv);
}

