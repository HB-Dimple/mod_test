mod_rsa
============
mod_rsa is an ejabberd module that will generate rsa key pairs for one one and muc end to end encryption.


--To get own public and private key--
<iq type='get' id='<generated id>'>
<query xmlns='jabber:e2eencryption' />
</iq>

--To get group public and private key--
<iq type='get' id='<generated id>'>
<query xmlns='jabber:e2eencryption' group_jid='room1@<your muc host name>' />
</iq>

<iq type='get' >
<query xmlns='jabber:e2eencryption' group_jid='room1@conference.192.168.36.1' />
</iq>

--To get other user public key--
<iq type='get' id='<generated id>'>
<query xmlns='jabber:e2eencryption' other_jid='test2@<your host name>' />
</iq>

<iq type='get' id='<generated id>'>
<query xmlns='jabber:e2eencryption' other_jid='test2@192.168.36.1' />
</iq>

Compilation and installation
----------------------------

- Follow https://docs.ejabberd.im/developer/extending-ejabberd/modules/