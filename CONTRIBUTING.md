[![master](https://travis-ci.org/checkpoint-restore/criu.svg?branch=master)](https://travis-ci.org/checkpoint-restore/criu)
[![development](https://travis-ci.org/checkpoint-restore/criu.svg?branch=criu-dev)](https://travis-ci.org/checkpoint-restore/criu)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/55251ec7db28421da4481fc7c1cb0cee)](https://www.codacy.com/app/xemul/criu?utm_source=github.com&amp;utm_medium=referral&amp;utm_content=xemul/criu&amp;utm_campaign=Badge_Grade)
<p align="center"><img src="https://criu.org/w/images/1/1c/CRIU.svg" width="128px"/></p>

## How to contribute to CRIU

CRIU project is (almost) the never-ending story, because we have to always keep up with the
Linux kernel supporting checkpoint and restore for all the features it provides. Thus we're
looking for contributors of all kinds -- feedback, bug reports, testing, coding, writing, etc.
Here are some useful hints to get involved.

* We have both -- [very simple](https://github.com/checkpoint-restore/criu/issues?q=is%3Aissue+is%3Aopen+label%3Aenhancement) and [more sophisticated](https://github.com/checkpoint-restore/criu/issues?q=is%3Aissue+is%3Aopen+label%3A%22new+feature%22) coding tasks;
* CRIU does need [extensive testing](https://github.com/checkpoint-restore/criu/issues?q=is%3Aissue+is%3Aopen+label%3Atesting);
* Documentation is always hard, we have [some information](https://criu.org/Category:Empty_articles) that is to be extracted from people's heads into wiki pages as well as [some texts](https://criu.org/Category:Editor_help_needed) that all need to be converted into useful articles;
* Feedback is expected on the github issues page and on the [mailing list](https://lists.openvz.org/mailman/listinfo/criu);
* We accept github pull requests and this is the preferred way to contribute to CRIU. If you prefer to send patches by email, you are welcome to send them to [CRIU development mailing list](https://lists.openvz.org/mailman/listinfo/criu).
Below we describe in more detail recommend practices for CRIU developemnt.
* Spread the word about CRIU in [social networks](http://criu.org/Contacts);
* If you're giving a talk about CRIU -- let us know, we'll mention it on the [wiki main page](https://criu.org/News/events);

### Seting up the developemnt environment

Although criu could be run as non-root (see [Security](https://criu.org/Security), development is better to be done as root. For example, some tests require root. So, it would be a good idea to set up some recent Linux distro on a virtual machine.

### Get the source code

The CRIU sources are tracked by Git. Official CRIU repo is at https://github.com/checkpoint-restore/criu.

The repository may contain multiple branches. Development happens in the **criu-dev** branch.

To clone CRIU repo and switch to the proper branch, run:

```
        git clone https://github.com/checkpoint-restore/criu criu
        cd criu
        git checkout criu-dev
```

### Compile

First, you need to install compile-time dependencies. Check [Installation dependencies](https://criu.org/Installation#Dependencies) for more info.

To compile CRIU, run:

```
        make
```

This should create the `./criu/criu` executable.

## Edit the source code

If you use ctags, you can generate the ctags file by running

```
        make tags
```

When you change the source code, please keep in mind the following code conventions:

* we prefer tabs and indentations to be 8 characters width
* CRIU mostly follows [Linux kernel coding style](https://www.kernel.org/doc/Documentation/process/coding-style.rst), but we are less strict than the kernel community.

Other conventions can be learned from the source code itself. In short, make sure your new code
looks similar to what is already there.

## Test your changes

CRIU comes with an extensive test suite. To check whether your changes introduce any regressions, run

```
         make test
```

The command runs [ZDTM Test Suite](https://criu.org/ZDTM_Test_Suite). Check for any error messages produced by it.

In case you'd rather have someone else run the tests, you can use travis-ci for your
own github fork of CRIU. It will check the compilation for various supported platforms,
as well as run most of the tests from the suite. See https://travis-ci.org/checkpoint-restore/criu
for more details.

## Sign your work

To improve tracking of who did what, we ask you to sign off the patches
that are to be emailed.

The sign-off is a simple line at the end of the explanation for the
patch, which certifies that you wrote it or otherwise have the right to
pass it on as an open-source patch.  The rules are pretty simple: if you
can certify the below:

### Developer's Certificate of Origin 1.1
    By making a contribution to this project, I certify that:

    (a) The contribution was created in whole or in part by me and I
        have the right to submit it under the open source license
        indicated in the file; or

    (b) The contribution is based upon previous work that, to the best
        of my knowledge, is covered under an appropriate open source
        license and I have the right under that license to submit that
        work with modifications, whether created in whole or in part
        by me, under the same open source license (unless I am
        permitted to submit under a different license), as indicated
        in the file; or

    (c) The contribution was provided directly to me by some other
        person who certified (a), (b) or (c) and I have not modified
        it.

    (d) I understand and agree that this project and the contribution
        are public and that a record of the contribution (including all
        personal information I submit with it, including my sign-off) is
        maintained indefinitely and may be redistributed consistent with
        this project or the open source license(s) involved.

then you just add a line saying

```
        Signed-off-by: Random J Developer <random at developer.example.org>
```

using your real name (please, no pseudonyms or anonymous contributions if
it possible).

Hint: you can use `git commit -s` to add Signed-off-by line to your
commit message. To append such line to a commit you already made, use
`git commit --amend -s`.

```
 From: Random J Developer <random at developer.example.org>
 Subject: [PATCH] Short patch description

 Long patch description (could be skipped if patch
 is trivial enough)

 Signed-off-by: Random J Developer <random at developer.example.org>
 ---
 Patch body here
```

## Submit your work upstream

We accept github pull requests and this is the preferred way to contribute to CRIU.
For that you should push your work to your fork of CRIU at [GitHub](https://github.com) and create a [pull request](https://help.github.com/en/github/collaborating-with-issues-and-pull-requests/about-pull-requests)

Historically, CRIU worked with mailing lists and patches so if you still prefer this way continue reading till the end of this section.

### Make a patch

To create a patch, run

```
    git format-patch --signoff origin/criu-dev
```

You might need to read GIT documentation on how to prepare patches
for mail submission. Take a look at http://book.git-scm.com/ and/or
http://git-scm.com/documentation for details. It should not be hard
at all.

We recommend to post patches using `git send-email`

```
  git send-email --cover-letter --no-chain-reply-to --annotate \
                 --confirm=always --to=criu@openvz.org criu-dev
```

Note that the `git send-email` subcommand may not be in
the main git package and using it may require installation of a
separate package, for example the "git-email" package in Fedora and
Debian.

If this is your first time using git send-email, you might need to
configure it to point it to your SMTP server with something like:

```
    git config --global sendemail.smtpServer stmp.example.net
```

If you get tired of typing `--to=criu@openvz.org` all the time,
you can configure that to be automatically handled as well:

```
    git config sendemail.to criu@openvz.org
```

If a developer is sending another version of the patch (e.g. to address
review comments), they are advised to note differences to previous versions
after the `---` line in the patch so that it helps reviewers but
doesn't become part of git history. Moreover, such patch needs to be prefixed
correctly with `--subject-prefix=PATCHv2` appended to
`git send-email` (substitute `v2` with the correct
version if needed though).

### Mail patches

The patches should be sent to CRIU development mailing list, `criu AT openvz.org`. Note that you need to be subscribed first in order to post. The list web interface is available at https://openvz.org/mailman/listinfo/criu; you can also use standard mailman aliases to work with it.

Please make sure the email client you're using doesn't screw your patch (line wrapping and so on).

{{Note| When sending a patch set that consists of more than one patch, please, push your changes in your local repo and provide the URL of the branch in the cover-letter}}

### Wait for response

Be patient. Most CRIU developers are pretty busy people so if
there is no immediate response on your patch — don't be surprised,
sometimes a patch may fly around a week before it gets reviewed.

## Continuous integration

Wiki article: [Continuous integration](https://criu.org/Continuous_integration)

CRIU tests are run for each series sent to the mailing list. If you get a message from our patchwork that patches failed to pass the tests, you have to investigate what is wrong.

We also recommend you to [enable Travis CI for your repo](https://criu.org/Continuous_integration#Enable_Travis_CI_for_your_repo) to check patches in your git branch, before sending them to the mailing list.
