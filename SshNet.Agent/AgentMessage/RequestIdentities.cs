using System;
using System.Collections.Generic;
using System.IO;
using Renci.SshNet;
using Renci.SshNet.Security;
using SshNet.Agent.Keys;

namespace SshNet.Agent.AgentMessage
{
    internal class RequestIdentities : IAgentMessage
    {
        private readonly SshAgent _agent;

        public RequestIdentities(SshAgent agent)
        {
            _agent = agent;
        }

        public void To(AgentWriter writer)
        {
            writer.Write((uint)1);
            writer.Write((byte)AgentMessageType.SSH2_AGENTC_REQUEST_IDENTITIES);
        }

        public object From(AgentReader reader)
        {
            _ = reader.ReadUInt32(); // msglen
            var answer = (AgentMessageType)reader.ReadByte();
            if (answer != AgentMessageType.SSH2_AGENT_IDENTITIES_ANSWER)
                throw new Exception($"Wrong Answer {answer}");

            var keys = new List<PrivateKeyAgent>();
            var numKeys = reader.ReadUInt32();
            var i = 0;
            while (i < numKeys)
            {
                var keyData = reader.ReadStringAsBytes();
                using var keyStream = new MemoryStream(keyData);
                using var keyReader = new AgentReader(keyStream);

                var keyType = keyReader.ReadString();
                Key? key = null;
                switch (keyType)
                {
                    case "ssh-rsa":
                        {
                            var exponent = keyReader.ReadBignum();
                            var modulus = keyReader.ReadBignum();
                            key = new RsaAgentKey(modulus, exponent, _agent, keyData);
                        }

                        break;
                    case "ecdsa-sha2-nistp256-cert-v01@openssh.com":
                        // Fallthrough
                    case "ecdsa-sha2-nistp384-cert-v01@openssh.com":
                        // Fallthrough
                    case "ecdsa-sha2-nistp521-cert-v01@openssh.com":
                        // TODO: implement me
                        /*
                         * https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys
                         * ECDSA certificate
                            string    "ecdsa-sha2-nistp256-cert-v01@openssh.com" |
                                      "ecdsa-sha2-nistp384-cert-v01@openssh.com" |
                                      "ecdsa-sha2-nistp521-cert-v01@openssh.com"
                            string    nonce
                            string    curve
                            string    public_key
                            uint64    serial
                            uint32    type
                            string    key id
                            string    valid principals
                            uint64    valid after
                            uint64    valid before
                            string    critical options
                            string    extensions
                            string    reserved
                            string    signature key
                            string    signature
                         */

                        {
                            // nonce
                            keyReader.ReadString();
                            // curve
                            keyReader.ReadString();
                            // public_key
                            keyReader.ReadString();
                            // serial
                            keyReader.ReadUInt64();
                            // type
                            keyReader.ReadUInt32();
                            // key id
                            keyReader.ReadString();
                            // valid principals
                            keyReader.ReadString();
                            // valid after
                            keyReader.ReadUInt64();
                            // valid before
                            keyReader.ReadUInt64();
                            // critical options
                            keyReader.ReadString();
                            // extensions
                            keyReader.ReadString();
                            // reserved
                            keyReader.ReadString();
                            // signature key
                            keyReader.ReadString();
                            // signature
                            keyReader.ReadString();
                        }

                        break;
                    case "ecdsa-sha2-nistp256":
                        // Fallthrough
                    case "ecdsa-sha2-nistp384":
                        // Fallthrough
                    case "ecdsa-sha2-nistp521":
                        {
                            var curve = keyReader.ReadString();
                            var q = keyReader.ReadBignum2();
                            key = new EcdsaAgentKey(curve, q, _agent, keyData);
                        }

                        break;
                    case "ssh-ed25519":
                        {
                            var pK = keyReader.ReadBignum2();
                            key = new ED25519AgentKey(pK, _agent, keyData);
                        }

                        break;
                    default:
                        throw new Exception($"Unsupported KeyType {keyType}");
                }

                var comment = reader.ReadString();
                if (key is not null)
                {
                    key.Comment = comment;
                    keys.Add(new PrivateKeyAgent(key));
                }

                i++;
            }

            return keys.ToArray();
        }
    }
}