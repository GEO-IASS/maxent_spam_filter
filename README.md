# MaxEnt Spam Filter

This is a Maximum Entropy (MaxEnt) spam filter. It is still highly experimental
but it still works. To use this filter you will need to download Mallet
(MAchine Learning for LanguagE Toolkit) from
[http://mallet.cs.umass.edu/](http://mallet.cs.umass.edu/). These scripts and
files act as a wrapper to Mallet.

Be aware this is still a very early prototype and the code is not meant for
general use yet. I hope to have time to make improvements.

## Installation
To install the spam filter:

1. Clone the repo to a local directory.
2. Download and extract mallet.
3. Create a symlink called mallet to the mallet-2.x.x directory.

## Configuration
Each script has its own configuration. Look at the script to make changes.

In order for the filter to know what's spam and what's ham, it must be trained.
To train the filter you will need to specify a list of email accounts that will
contain both spam and legitimate email. Each account must store its email in
maildir format. Each account must have a folder called Spam. This is where the
unwanted email will be stored. All other email messages will be considered ham.

To specify the location of the mailboxes set `mail_dir` in
`extract_training_features`. Then create a file called `accounts` in this same
directory and add the name of the mailboxes one per line.

For example, if your mailbox directories are stored as follows:

  /srv/mail/example.com/bob
  /srv/mail/example.com/joe
  /srv/mail/example.net/mary

Your `mail_dir` value will be `/srv/mail` and your accounts file will contain:

  example.com/bob
  example.com/joe
  example.net/mary

`extract_training_features` also has a few additional settings, such as where
the features and MaxEnt model will be stored (the `data_dir` value).

Addtional configuration values (such as the location of the filter and Mallet)
are found in `train` and `validate`.

## Training
Once configured, you can train the filter by running `train`. It will extract
features and create a model that will be used for classifying incoming email.

## Filtering Email
Once trained you can filter email by using the `classify` script. You can also
use the `filter_new_messages` to look at all new emails and attempt to
classify. These scripts may not work properly, so I'd recommend you don't use
them.

The best way to filter email is during the SMTP session. `spamd.py` is a basic
spam filter that mimics the filtering calls of SpamAssassin's spamd filter.
You can use spamd.py from Xxim by adding the following to your `acl_check_data`
section of exim.conf:

` warn spam = nobody
  add_header = Spam: Yes\n\
               X-Spam: Yes
`

(Make sure to also configure `spamd_address` with the IP address of the server
where spamd.py is running.)

Finally, add the following sieve filter to your global mail system:

`require [ "fileinto", "mailbox" ];

if header :is "Spam" "Yes"
{
    fileinto :create "Spam";
	stop;
}
`

## Help
As you can see this work is still extremly rough. Contact the author for
questions.

