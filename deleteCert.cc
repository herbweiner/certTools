/*-----------------------------------------------------------------------------
 *	deleteCert, Copyright (C) 2021 Herb Weiner. All rights reserved.
 *	CC BY-SA 4.0: https://creativecommons.org/licenses/by-sa/4.0
 *-----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/stat.h>

extern int					errno;
extern const char * const	sys_errlist[];

static const char			*my_name;
static int					opt_path = 0;
static int					opt_expired = 0;
static int					opt_force = 0;
static const char			*opt_issuer = "";
static const char			*opt_subject = "";
static int					delete_number = -1;
static int					opt_test = 0;

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
	int							i = strlen (buffer) - 1;

	while ((i >= 0)
	  && ((buffer[i] == ' ') || (buffer[i] == '\t') || (buffer[i] == '\n') || (buffer[i] == '\r') || (buffer[i] == '\f')))
		buffer[i--] = '\0';
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		parseNames - Parse Organization and Common Names
 *
 *	SYNOPSIS
 *		static void
 *		parseNames(
 *			const char		*buffer,			- Names to be Parsed
 *			char			*organizationName,	- Organization Name
 *			char			*commonName)		- Common Name
 *
 *	RETURN VALUE
 *		None.
 *
 *	DESCRIPTION
 *		This function parses the Organization Name and the Common Name
 *-----------------------------------------------------------------------------
 */

static void parseNames (const char *buffer, char *organizationName, char *commonName)
{
	int							i = strlen (buffer) - 1;
	const char					*cp;
	char						*dp;

	cp = strstr (buffer, "O = ");
	if (cp == (const char *) NULL)
		*organizationName = '\0';
	else
	{
		strcpy (organizationName, cp + 4);

		dp = strstr (organizationName, ", CN =");
		if (dp != (const char *) NULL)
			*dp = '\0';
	}

	cp = strstr (buffer, "CN = ");
	if (cp == (const char *) NULL)
		*commonName = '\0';
	else
		strcpy (commonName, cp + 5);
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		editCertFile - Edit the Certificate File
 *
 *	SYNOPSIS
 *		void
 *		editCertFile(
 *			const char		*oldName			- Existing Certificate File
 *			const char		*newName			- Backup Certificate File
 *			const bool		*removeFlags)		- Array of Flags
 *
 *	RETURN VALUE
 *		None
 *
 *	DESCRIPTION
 *		Edit one Certificate File.
 *		*	Backup Original File
 *		*	Write New File
 *		*	Change Ownership and Permissions
 *-----------------------------------------------------------------------------
 */

void editCertFile (const char *oldName, const char *newName, const bool *removeFlags)
{
	int							count = 0;
	int							result;
	char						buffer [4096];
	bool						inCert = false;
	bool						blankLineNeeded = false;
	FILE						*inFile;
	FILE						*outFile;
	struct stat					in_stat;

	result = rename (oldName, newName);
	if (result == -1)
	{
		fprintf (stderr, "%s: rename (%s, %s) failed <%s>\n", my_name, oldName, newName, sys_errlist [errno]);
		return;
	}

	inFile = fopen (newName, "r");
	if (inFile == (FILE *) NULL)
	{
		fprintf (stderr, "%s: open (%s) failed <%s>\n", my_name, newName, sys_errlist [errno]);

		result = rename (newName, oldName);
		if (result == -1)
			fprintf (stderr, "%s: rename (%s, %s) failed <%s>\n", my_name, newName, oldName, sys_errlist [errno]);

		return;
	}

	outFile = fopen (oldName, "w");
	if (outFile == (FILE *) NULL)
	{
		fprintf (stderr, "%s: open (%s) failed <%s>\n", my_name, oldName, sys_errlist [errno]);

		fclose (inFile);

		result = rename (newName, oldName);
		if (result == -1)
			fprintf (stderr, "%s: rename (%s, %s) failed <%s>\n", my_name, newName, oldName, sys_errlist [errno]);

		return;
	}

	while (fgets (buffer, sizeof (buffer), inFile) != NULL)
	{
		trim (buffer);
		if (inCert)
		{
			if (! (removeFlags [count - 1]))
				fprintf (outFile, "%s\n", buffer);

			if (strcmp (buffer, "-----END CERTIFICATE-----") == 0)
			{
				inCert = false;

				if (! (removeFlags [count - 1]))
					blankLineNeeded = true;
			}
		}
		else
		{
			if (strcmp (buffer, "-----BEGIN CERTIFICATE-----") == 0)
			{
				count++;
				inCert = true;

				if (! (removeFlags [count - 1]))
				{
					if (blankLineNeeded)
					{
						fprintf (outFile, "\n");
						blankLineNeeded = false;
					}
					fprintf (outFile, "%s\n", buffer);
				}
			}
		}
	}

	/*-------------------------------------------------------------------------
	 *	Get Ownership and Permissions of Original (Backup) File (newName)
	 *-------------------------------------------------------------------------
	 */

	result = fstat (fileno (inFile), &in_stat);
	if (result == -1)
		fprintf (stderr, "%s: fstat (%s) failed <%s>\n", my_name, newName, sys_errlist [errno]);

	/*-------------------------------------------------------------------------
	 *	Change Permissions of Original (Backup) File (newName) to Prevent Write
	 *-------------------------------------------------------------------------
	 */

	result = fchmod (fileno (inFile), (in_stat.st_mode & (S_IRUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)));
	if (result == -1)
		fprintf (stderr, "%s: fchmod (%s) failed <%s>\n", my_name, newName, sys_errlist [errno]);

	/*-------------------------------------------------------------------------
	 *	Change Ownership and Permissions of New File (oldName)
	 *-------------------------------------------------------------------------
	 */

	result = fchmod (fileno (outFile), (in_stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)));
	if (result == -1)
		fprintf (stderr, "%s: fchmod (%s) failed <%s>\n", my_name, oldName, sys_errlist [errno]);

	result = fchown (fileno (outFile), in_stat.st_uid, in_stat.st_gid);
	if (result == -1)
		fprintf (stderr, "%s: fchown (%s) failed <%s>\n", my_name, oldName, sys_errlist [errno]);

	fclose (inFile);
	fclose (outFile);
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		deleteOneCert - Delete One Certificate
 *
 *	SYNOPSIS
 *		void
 *		deleteOneCert(
 *			const char		*filename)			- Filename to process
 *
 *	RETURN VALUE
 *		None
 *
 *	DESCRIPTION
 *		Process one Certificate File.
 *		*	for each cert in file, parse and save info
 *		*	determine whether cert needs to be deleted
 *		*	If any cert need to be deleted, edit file
 *		*	Produce output
 *
 *	NOTES
 *		C=	Country.
 *		ST=	State.
 *		O=	Organization.
 *		CN=	Common Name.
 *-----------------------------------------------------------------------------
 */

void deleteOneCert (const char *filename)
{
	int							i;
	int							result;
	const int					MAXIMUM_CERTIFICATES = 16;
	const int					MAXIMUM_LENGTH = 1024;
	char						command [4096];
	char						buffer [4096];
	char						wd [4096];
	char						certfile [4096];
	char						backupFilename [4096];
	char						issuer [MAXIMUM_CERTIFICATES] [MAXIMUM_LENGTH];
	char						validity_message [MAXIMUM_CERTIFICATES] [MAXIMUM_LENGTH];
	char						validity_range [MAXIMUM_CERTIFICATES] [MAXIMUM_LENGTH];
	char						subject [MAXIMUM_CERTIFICATES] [MAXIMUM_LENGTH];
	bool						remove [MAXIMUM_CERTIFICATES];
	char						organizationName [1024];
	char						commonName [1024];
	const char					*reportFilename;
	const char					*cp;
	bool						editFile = false;
	bool						updateFile = false;
	FILE						*inFile;
	FILE						*outFile;
	FILE						*p;
	int							totalCount = 0;
	int							deleteCount = 0;
	struct stat					in_stat;
	struct stat					out_stat;

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

	result = stat (filename, &in_stat);
	if (result == -1)
	{
		fprintf (stderr, "%s: stat (%s) failed <%s>\n", my_name, filename, sys_errlist [errno]);
		return;
	}

	if (opt_path)
		sprintf (command, "decodeCert -p %s", filename);
	else
		sprintf (command, "decodeCert %s", filename);

	p = popen (command, "r");
	if (p == (FILE *) NULL)
	{
		fprintf (stderr, "%s: popen (%s) failed <%s>\n", my_name, command, sys_errlist [errno]);
		return;
	}

	while (fgets (buffer, sizeof (buffer), p) != NULL)
	{
		trim (buffer);

		if (strncmp (buffer, "========", 8) == 0)
		{
			totalCount++;

			issuer [totalCount - 1] [0] = '\0';
			validity_message [totalCount - 1] [0] = '\0';
			validity_range [totalCount - 1] [0] = '\0';
			subject [totalCount - 1] [0] = '\0';
			remove [totalCount - 1] = false;

			if ((totalCount == delete_number) && (! (remove [totalCount - 1])))
			{
				remove [totalCount - 1] = true;
				deleteCount++;
			}

			continue;
		}

		if ((cp = strstr (buffer, "Issuer: ")) != (const char *) NULL)
		{
			strcpy (issuer [totalCount - 1], cp + 8);
			if (! (remove [totalCount - 1]))
			{
				parseNames (issuer [totalCount - 1], organizationName, commonName);
				if ((*opt_issuer != '\0') && ((strcasecmp (organizationName, opt_issuer) == 0) || (strcasecmp (commonName, opt_issuer) == 0)))
				{
					remove [totalCount - 1] = true;
					deleteCount++;
				}
			}
			continue;
		}

		if ((cp = strstr (buffer, "Validity")) != (const char *) NULL)
		{
			if (cp [8] != '\0')
			{
				strcpy (validity_message [totalCount - 1], cp + 9);
				if ((opt_expired) && (! (remove [totalCount - 1])))
				{
					remove [totalCount - 1] = true;
					deleteCount++;
				}
			}
			continue;
		}

		if ((cp = strstr (buffer, "Not Before: ")) != (const char *) NULL)
		{
			strcpy (validity_range [totalCount - 1], cp + 12);
			continue;
		}

		if ((cp = strstr (buffer, "Not After : ")) != (const char *) NULL)
		{
			strcat (validity_range [totalCount - 1], " - ");
			strcat (validity_range [totalCount - 1], cp + 12);
			continue;
		}

		if ((cp = strstr (buffer, "Subject: ")) != (const char *) NULL)
		{
			strcpy (subject [totalCount - 1], cp + 9);
			if (! (remove [totalCount - 1]))
			{
				parseNames (subject [totalCount - 1], organizationName, commonName);
				if ((*opt_subject != '\0') && ((strcasecmp (organizationName, opt_subject) == 0) || (strcasecmp (commonName, opt_subject) == 0)))
				{
					remove [totalCount - 1] = true;
					deleteCount++;
				}
			}
			continue;
		}
	}

	pclose (p);

	*buffer = '\0';
	sprintf (command, "ls -l %s", certfile);
	p = popen (command, "r");
	if (p != (FILE *) NULL)
	{
		fgets (buffer, sizeof (buffer), p);
		trim (buffer);
		pclose (p);
	}

	/*-------------------------------------------------------------------------
	 *	Need to report Filename, permissions, owner, group, timestamp, size, [BACKUP TO ...]
	 *-------------------------------------------------------------------------
	 */

	if (*buffer == '\0')
		reportFilename = certfile;
	else
		reportFilename = buffer;

	if (deleteCount == 0)
		fprintf (stdout, "######## %s, %d Certificates in File, Delete %d (File NOT Modified)\n", reportFilename, totalCount, deleteCount);
	else if (deleteCount == totalCount)
		fprintf (stdout, "######## %s, %d Certificates in File, Delete %d (Entire file must be deleted)\n", reportFilename, totalCount, deleteCount);
	else if (opt_test)
		fprintf (stdout, "######## %s, %d Certificates in File, Delete %d (File not updated in Test Mode)\n", reportFilename, totalCount, deleteCount);
	else
	{
		updateFile = true;
		cp = strrchr (certfile, '.');
		if (cp == (const char *) NULL)
			sprintf (backupFilename, "%s-BACKUP", certfile);
		else
			sprintf (backupFilename, "%.*s-BACKUP.%s", (int) (cp - certfile), certfile, cp + 1);

		result = stat (backupFilename, &out_stat);
		if (result == 0)
		{
			if (opt_force)
			{
				fprintf (stdout, "######## %s, %d Certificates in File, Delete %d (Backup %s will be overwritten in Force Mode)\n", reportFilename, totalCount, deleteCount, backupFilename);

				/*-------------------------------------------------------------
				 *	Change permissions of backup file to allow overwrite.
				 *-------------------------------------------------------------
				 */

				result = chmod (backupFilename, (in_stat.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)));
				if (result == -1)
					fprintf (stderr, "%s: chmod (%s) failed <%s>\n", my_name, backupFilename, sys_errlist [errno]);
			}
			else
			{
				fprintf (stdout, "######## %s, %d Certificates in File, Delete %d (Backup %s already exists so %s will NOT be updated)\n", reportFilename, totalCount, deleteCount, backupFilename, certfile);
				updateFile = false;
			}
		}
		else
			fprintf (stdout, "######## %s, %d Certificates in File, Delete %d (Backup to %s)\n", reportFilename, totalCount, deleteCount, backupFilename);
	}

	for (i = 0; i < totalCount; i++)
		fprintf (stdout, "%3d. %s %-21.21s %s; Issuer <%s>; Subject <%s>\n", i + 1, remove [i] ? "DELETE" : "      ", validity_message [i], validity_range [i], issuer[i], subject [i]);

	if (updateFile)
		editCertFile (certfile, backupFilename, remove);
}

/*-----------------------------------------------------------------------------
 *	NAME
 *		main - deleteCert main function
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
 *		This is the main function for deleteCert.
 *-----------------------------------------------------------------------------
 */

int main (int argc, const char *argv[])
{
	int							i;
	int							opt_help = 0;
	int							opt_debug = 0;
	int							opt_verbose = 0;
	const char					*opt_number = "";
	const char					*reportFilename;
	char						wd [4096];
	char						certfile [4096];
	char						command [4096];
	char						buffer [4096];
	FILE						*p;

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
		{ "-e",	&opt_expired,			"Delete Expired Certificates"         },
		{ "-f",	&opt_force,				"Overwrite Backup"                    },
		{ "=i",	&opt_issuer,			"Delete by Matching Issuer"           },
		{ "=n",	&opt_number,			"Delete by Matching Certificat Number"},
		{ "-p",	&opt_path,				"Display Full Pathname"               },
		{ "=s",	&opt_subject,			"Delete by Matching Subject"          },
		{ "-t",	&opt_test,				"Test Mode - Do not delete"           },
		{ "-v",	&opt_verbose,			"Verbose Output"                      },
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

	if (*opt_number == '\0')
		delete_number = -1;
	else
	{
		if (argc > 1)
		{
			fprintf (stderr, "%s: -n may be specified only with a single file\n", my_name);
			opt_help = 1;
		}

		delete_number = (int) strtol (opt_number, (char **) NULL, 10);
	}

	if (opt_help)
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

	/*-------------------------------------------------------------------------
	 *	Process all arguments EXCEPT BACKUP files
	 *-------------------------------------------------------------------------
	 */

	for (i = 0; i < argc; i++)
	{
		if ((strstr (argv [i], "-BACKUP.") != (const char *) NULL) && (argc > 1))
		{
			if (opt_path && ((*(argv [i])) != '/'))
			{
				getcwd (wd, sizeof (wd));
				if (strncmp (argv [i], "./", 2) == 0)
					sprintf (certfile, "%s/%s", wd, argv [i] + 2);
				else
					sprintf (certfile, "%s/%s", wd, argv [i]);
			}
			else
				strcpy (certfile, argv [i]);

			*buffer = '\0';
			sprintf (command, "ls -l %s", certfile);
			p = popen (command, "r");
			if (p != (FILE *) NULL)
			{
				fgets (buffer, sizeof (buffer), p);
				trim (buffer);
				pclose (p);
			}

			if (*buffer == '\0')
				reportFilename = certfile;
			else
				reportFilename = buffer;

			fprintf (stdout, "######## %s: Ignoring BACKUP File\n", reportFilename);
		}
		else
			deleteOneCert (argv [i]);
	}
}
