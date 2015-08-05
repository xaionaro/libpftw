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


int cb_print(
	const char *fpath,
	const struct stat *sb,
	int typeflag,
	struct FTW *ftwbuf,
	void *arg)
{

	printf("%s\n", fpath);

	return FTW_CONTINUE;
}

int main() {
	fprintf(stderr, "pftw_init(8) -> %i\n", pftw_init(8));
	fprintf(stderr, "pftw() -> %i\n", pftw("/var", cb_print, 0, FTW_PHYS|FTW_ACTIONRETVAL, NULL));
	fprintf(stderr, "pftw_deinit() -> %i\n", pftw_deinit());

	return 0;
}

