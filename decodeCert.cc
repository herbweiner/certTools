/*-----------------------------------------------------------------------------
 *	decodeCert, Copyright (C) 2021 Herb Weiner. All rights reserved.
 *	CC BY-SA 4.0: https://creativecommons.org/licenses/by-sa/4.0
 *-----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <xlocale.h>

extern int					errno;
extern const char * const	sys_errlist[];

static const char			*my_name;
static char					tempFile [1024];
static int					opt_debug = 0;
static int					opt_path = 0;
static int					opt_verbose = 0;

/*-----------------------------------------------------------------------------
 *	NAME
 *		trim - Remove trailing blanks, tabs, and newlines
 *
 *	SYNOPSIS
 *		static void
 *		trim(
 *			char			*buffer)			- Buffer to be trimmed
 *
 *	RETURN VALUE
 *		None.
 *
 *	DESCRIPTION
 *		This function removes trailing whitespace from a null terminated
 *		string.
 *-----------------------------------------------------------------------------
 */

static void trim (char *buffer)
{
	int					i = strlen (buffer) - 1;

	while ((i >= 0)
	  && ((buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\n') || (buffer[i] == '\r') || (buffer[i] == '\f')))
		buffer[i--] = '\0';
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		parse_openssl - Parse openssl output
 *
 *	SYNOPSIS
 *		void
 *		parse_openssl(
 *			FILE			*p)					- Input Pipe
 *
 *	RETURN VALUE
 *		None
 *
 *	DESCRIPTION
 *		This function parses the output of openssl.
 *-----------------------------------------------------------------------------
 */

void parse_openssl (FILE *p)
{
	char						buffer [4096];
	char						validity_buffer [4096];
	char						before_buffer [4096];
	char						parsed_time_string [256];
	const char					*cp;
	char						*vp;
	time_t						now;
	time_t						parsed;
	struct tm					parsed_time_struct;

	time (&now);

	while (fgets (buffer, sizeof (buffer), p) != NULL)
	{
		trim (buffer);
		if (opt_verbose)
		{
			/*-----------------------------------------------------------------
			 *	Show all output from openssl.
			 *-----------------------------------------------------------------
			 */

			fprintf (stdout, "%s\n", buffer);
			fflush (stdout);
		}
		else
		{
			/*-----------------------------------------------------------------
			 *	Show only the most important output from openssl.
			 *-----------------------------------------------------------------
			 */

			if ((strncmp (buffer, "========", 8) == 0)
			  || (strstr (buffer, "Issuer:") != (const char *) NULL)
			  || (strstr (buffer, "Subject:") != (const char *) NULL))
			{
				fprintf (stdout, "%s\n", buffer);
				fflush (stdout);
			}
			else if ((cp = strstr (buffer, "Validity")) != (const char *) NULL)
				strcpy (validity_buffer, buffer);
			else if ((cp = strstr (buffer, "Not Before: ")) != (const char *) NULL)
			{
				strcpy (before_buffer, buffer);
				strptime (cp + 12, "%b %e %T %Y %Z", &parsed_time_struct);
				parsed = mktime (&parsed_time_struct);

				if (parsed > now)
				{
					vp = validity_buffer + strlen (validity_buffer);
					strcpy (vp, " *** NOT YET VALID ***");
				}

				if (opt_debug)
				{
					strftime (parsed_time_string, sizeof (parsed_time_string), "%Y-%m-%d-%a %T %Z", &parsed_time_struct);
					fprintf (stdout, "*** PARSED NOT BEFORE (%s): %s\n", cp + 12, parsed_time_string);
				}
			}
			else if ((cp = strstr (buffer, "Not After : ")) != (const char *) NULL)
			{
				strptime (cp + 12, "%b %e %T %Y %Z", &parsed_time_struct);
				parsed = mktime (&parsed_time_struct);

				if (parsed < now)
				{
					vp = validity_buffer + strlen (validity_buffer);
					strcpy (vp, " *** EXPIRED ***");
				}

				if (opt_debug)
				{
					strftime (parsed_time_string, sizeof (parsed_time_string), "%Y-%m-%d-%a %T %Z", &parsed_time_struct);
					fprintf (stdout, "*** PARSED NOT AFTER (%s): %s\n", cp + 12, parsed_time_string);
				}

				fprintf (stdout, "%s\n", validity_buffer);
				fprintf (stdout, "%s\n", before_buffer);
				fprintf (stdout, "%s\n", buffer);
				fflush (stdout);
			}
		}
	}
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		decodeOneCert - Decode One Certificate
 *
 *	SYNOPSIS
 *		void
 *		decodeOneCert(
 *			const char		*filename)			- Filename to process
 *
 *	RETURN VALUE
 *		None
 *
 *	DESCRIPTION
 *		Process one Certificate File. This file may contain a certificate
 *		chain consisting of multiple individual certificates. Each certiicate
 *		must be individually decoded by openssl.
 *-----------------------------------------------------------------------------
 */

void decodeOneCert (const char *filename)
{
	char						command [4096];
	char						buffer [4096];
	char						wd [4096];
	char						certfile [4096];
	FILE						*inFile;
	FILE						*outFile;
	FILE						*p;
	int							count = 0;
	bool						inCert = false;

	if (opt_path && (*filename != '/'))
	{
		getcwd (wd, sizeof (wd));
		if (strncmp (filename, "./", 2) == 0)
			sprintf (certfile, "%s/%s", wd, filename + 2);
		else
			sprintf (certfile, "%s/%s", wd, filename);
	}
	else
		strcpy (certfile, filename);

	inFile = fopen (filename, "r");
	if (inFile == (FILE *) NULL)
	{
		fprintf (stderr, "%s: fopen (%s) failed <%s>\n", my_name, filename, sys_errlist [errno]);
		return;
	}

	while (fgets (buffer, sizeof (buffer), inFile) != NULL)
	{
		trim (buffer);
		if (inCert)
		{
			fprintf (outFile, "%s\n", buffer);

			if (strcmp (buffer, "-----END CERTIFICATE-----") == 0)
			{
				fclose (outFile);
				inCert = false;

				sprintf (command, "openssl x509 -in %s -text -noout", tempFile);
				p = popen (command, "r");
				parse_openssl (p);
				pclose (p);
				unlink (tempFile);
			}
		}
		else
		{
			if (strcmp (buffer, "-----BEGIN CERTIFICATE-----") == 0)
			{
				count++;
				fprintf (stdout, "======== %s, Certificate %d\n", certfile, count);
				fflush (stdout);
				outFile = fopen (tempFile, "w");
				inCert = true;
				fprintf (outFile, "%s\n", buffer);
			}
		}
	}

	if (inCert)
		fclose (outFile);

	if (count > 1)
	{
		fprintf (stdout, "######## %s, %d Certificates in File\n", certfile, count);
		fflush (stdout);
	}

	fclose (inFile);
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		main - decodeCert main function
 *
 *	SYNOPSIS
 *		int
 *		main(
 *			int				argc,				- Number of Arguments
 *			const char		*argv[])			- Argument Vector
 *
 *	RETURN VALUE
 *		None
 *
 *	DESCRIPTION
 *		This is the main function for decodeCert.
 *-----------------------------------------------------------------------------
 */

int main (int argc, const char *argv[])
{
	int							i;
	int							opt_help = 0;
	char						buffer [4096];

	typedef struct
	{
		const char * const	name;
		void				*value;
		const char * const	help;
	}
	option_structure;

	static option_structure option_list [] =
	{
		{ "-?",	&opt_help,				"Display these help messages"         },
		{ "-h",	&opt_help,				"Display these help messages"         },
		{ "-d",	&opt_debug,				"Debug Output"                        },
		{ "-p",	&opt_path,				"Display Full Pathname"               },
		{ "-v",	&opt_verbose,			"Verbose (Full) Output from openssl"  },
	};
	int	number_of_options = sizeof (option_list) / sizeof (option_structure);

	/*-------------------------------------------------------------------------
	 *	Startup and Check Options.
	 *-------------------------------------------------------------------------
	 */

	my_name = strrchr (argv[0], '/');
	if (my_name == (char *) NULL)
		my_name = argv[0];
	else
		my_name++;

	argv++;
	argc--;

	while ((argc > 0) && (**argv == '-'))
	{
		for (i = 0; i < number_of_options; i++)
		{
			if (option_list[i].name[0] == '-')
			{
				if (strcmp (option_list [i].name, *argv) == 0)
				{
					*((int *) (option_list [i].value)) ^= 1;
					argv++;
					argc--;
					break;
				}
			}
			if (option_list[i].name[0] == '=')
			{
				if (strcmp (option_list [i].name + 1, *argv + 1) == 0)
				{
					if (argc > 1)
					{
						argv++;
						argc--;
						*((const char **) (option_list [i].value)) = *argv;
						argv++;
						argc--;
						break;
					}
					else
						fprintf (stderr, "Error: required value missing for %s\n", *argv);
				}
			}
		}
		if (i == number_of_options)
		{
			fprintf (stderr, "Error: unrecognized option %s\n", *argv);
			opt_help = 1;
			break;
		}
	}

	if (opt_help || (argc == 0))
	{
		fprintf (stderr, "usage: %s -options filename...\n", my_name);
		fprintf (stderr, "options:\n");
		for (i = 0; i < number_of_options; i++)
		{
			if (option_list[i].name[0] == '-')
				fprintf (stderr, "  %s: %s [%s]\n",
							option_list [i].name, option_list [i].help,
							*((int *) (option_list [i].value)) ? "enabled" : "disabled");
			else
				fprintf (stderr, "  -%s value: %s [%s]\n",
							option_list [i].name + 1, option_list [i].help,
							*((const char **) (option_list [i].value)) ? (const char *) *((const char **) (option_list [i].value)) : "<UNDEFINED>");
		}
		exit (1);
	}

	sprintf (tempFile, "/tmp/%s-%d.pem", my_name, getpid ());

	/*-------------------------------------------------------------------------
	 *	Process all arguments.
	 *-------------------------------------------------------------------------
	 */

	for (i = 0; i < argc; i++)
		decodeOneCert (argv [i]);
}
