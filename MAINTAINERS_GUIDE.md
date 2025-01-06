## Introduction

Dear maintainer. Thank you for investing the time and energy to help
make CRIU as useful as possible. Maintaining a project is difficult,
sometimes unrewarding work. Sure, you will contribute cool features
to the project, but most of your time will be spent reviewing patches,
cleaning things up, documenting, answering questions, justifying design
decisions - while everyone else will just have fun! But remember -- the
quality of the maintainers work is what distinguishes the good projects
from the great. So please be proud of your work, even the unglamorous
parts, and encourage a culture of appreciation and respect for *every*
aspect of improving the project -- not just the hot new features.

Being a maintainer is a time consuming commitment and should not be
taken lightly. This document is a manual for maintainers old and new.
It explains what is expected of maintainers, how they should work, and
what tools are available to them.

This is a living document - if you see something out of date or missing,
speak up!

## What are a maintainer's responsibility?

Part of a healthy project is to have active maintainers to support the
community in contributions and perform tasks to keep the project running.
It is every maintainer's responsibility to:

  * Keep the community a friendly place
  * Deliver prompt feedback and decisions on pull requests and mailing
    list threads
  * Encourage other members to help each other, especially in cases the
    maintainer is overloaded or feels the lack of needed expertise
  * Make sure the changes made respects the philosophy, design and
    roadmap of the project

## How are decisions made?

CRIU is an open-source project with an open design philosophy. This
means that the repository is the source of truth for EVERY aspect of the
project. *If it's part of the project, it's in the repo. It's in the
repo, it's part of the project.*

All decisions affecting CRIU, big and small, follow the same 3 steps:

  * Submit a change. Anyone can do this

  * Discuss it. Anyone can and is encouraged to do this

  * Accept or decline it. Only maintainers do this

*I'm a maintainer, should I make pull requests / send patches too?*

Yes. Nobody should ever push to the repository directly. All changes
should be made through submitting (and accepting) the change.

### Two-steps decision making ###

Since CRIU is extremely complex piece of software we try double hard
not to make mistakes, that would be hard to fix in the future. In order
to facilitate this, the "final" decision is made in two stages:

  * We definitely want to try something out

  * We think that the attempt was successful

Respectively, new features get accepted first into the *criu-dev* branch and
after they have been validated they are merged into the *master* branch. Yet,
urgent bug fixes may land directly in the master branch. If a change in
the criu-dev branch is considered to be bad (whatever it means), then it
can be reverted without propagation to the master branch. Reverting from
the master branch is expected not to happen at all, but if such an
extraordinary case occurs, the impact of this step, especially the question
of backward compatibility, should be considered in the most careful manner.

## Who decides what?

All decisions can be expressed as changes to the repository (either in the
form of pull requests, or patches sent to the mailing list), and maintainers
make decisions by merging or rejecting them. Review and approval or
disagreement can be done by anyone and is denoted by adding a respective
comment in the pull request. However, merging the change into either branch
only happens after approvals from maintainers.

In order for a patch to be merged into the criu-dev branch at least two
maintainers should accept it. In order for a patch to be merged into the
master branch the majority of maintainers should decide that (then prepare
a pull request, submit it, etc.).

Overall the maintainer system works because of mutual respect across the
maintainers of the project. The maintainers trust one another to make
decisions in the best interests of the project. Sometimes maintainers
can disagree and this is part of a healthy project to represent the point
of views of various people. In the case where maintainers cannot find
agreement on a specific change the role of a Chief Maintainer comes into
play.

### Chief maintainer

The chief maintainer for the project is responsible for overall architecture
of the project to maintain conceptual integrity. Large decisions and
architecture changes should be reviewed by the chief maintainer.

Also the chief maintainer has the veto power on any change submitted
to any branch. Naturally, a change in the criu-dev branch can be reverted
after a chief maintainer veto, a change in the master branch must be
carefully reviewed by the chief maintainer and vetoed in advance.

### How are maintainers added (and removed)?

The best maintainers have a vested interest in the project. Maintainers
are first and foremost contributors that have shown they are committed to
the long term success of the project. Contributors wanting to become
maintainers are expected to be deeply involved in contributing code,
patches review, and paying needed attention to the issues in the project.
Just contributing does not make you a maintainer, it is about building trust
with the current maintainers of the project and being a person that they can
rely on and trust to make decisions in the best interest of the project.

When a contributor wants to become a maintainer or nominate someone as a
maintainer, one can submit a "nomination", which technically is the
respective modification to the `MAINTAINERS` file. When a maintainer feels
they is unable to perform the required duties, or someone else wants to draw
the community attention to this fact, one can submit a "(self-)removing"
change.

The final vote to add or to remove a maintainer is to be approved by the
majority of current maintainers (with the chief maintainer having veto power
on that too).

One might have noticed, that the chief maintainer (re-)assignment is not
regulated by this document. That's true :) However, this can be done. If
the community decides that the chief maintainer needs to be changed the
respective "decision making rules" are to be prepared, submitted and
accepted into this file first.

Good luck!
