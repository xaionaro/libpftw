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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define PFTW_MAX_THREADS_BITS		8
#define PFTW_MAX_QUEUE_LENGTH_BITS	2
#define PFTW_DIFFICULTY_THRESHOLD	4

#define PFTW_MAX_THREADS	(1 <<  PFTW_MAX_THREADS_BITS)
#define PFTW_MAX_QUEUE_LENGTH	(1 << (PFTW_MAX_THREADS_BITS + PFTW_MAX_QUEUE_LENGTH_BITS))
#define	PFTW_ALLOCPORTION	(1<<4)


struct FTW;

typedef int (*pftw_callback_t) (
	const char *fpath,
	const struct stat *sb,
	int typeflag,
	struct FTW *ftwbuf,
	void *arg);

extern int pftw_init(int num_threads);
extern int pftw(const char *dirpath, pftw_callback_t fn, int nopenfd, int flags, void *arg);
extern int pftw_deinit();

