# bot.py
# Python 3.11+ | discord.py 2.3+ | cryptography 42+
# pip install "discord.py>=2.3" cryptography

import discord
from discord import app_commands
from discord.ext import commands
import io
import zipfile
import uuid
import datetime
import plistlib

from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import serialize_key_and_certificates

# ── config ───────────────────────────────────────────────────────────────────
BOT_TOKEN  = "YOUR_BOT_TOKEN_HERE"
GUILD_ID   = None
CERT_DAYS  = 365
PASSWORD   = "WonkaBar123"
# ─────────────────────────────────────────────────────────────────────────────


def build_ca():
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,       "RoostCA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "RoostAuthority"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,      "US"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_DAYS * 3))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ), critical=True,
        )
        .sign(key, hashes.SHA256(), default_backend())
    )
    return key, cert


def build_leaf(bundle_id: str, team_id: str, ca_key, ca_cert):
    key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME,              f"{team_id}: {bundle_id}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME,        team_id),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "iOS Distribution"),
        x509.NameAttribute(NameOID.COUNTRY_NAME,             "US"),
    ])
    now = datetime.datetime.utcnow()
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=CERT_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False,
                key_encipherment=True,  data_encipherment=False,
                key_agreement=False,    key_cert_sign=False,
                crl_sign=False,         encipher_only=False,
                decipher_only=False,
            ), critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=False,
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(bundle_id)]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256(), default_backend())
    )
    return key, cert


def build_p12(leaf_key, leaf_cert, ca_cert) -> bytes:
    return serialize_key_and_certificates(
        name=leaf_cert.subject.get_attributes_for_oid(
            NameOID.COMMON_NAME)[0].value.encode(),
        key=leaf_key,
        cert=leaf_cert,
        cas=[ca_cert],
        encryption_algorithm=serialization.BestAvailableEncryption(
            PASSWORD.encode()
        ),
    )


def build_mobileprovision(bundle_id: str, team_id: str, cert: x509.Certificate) -> bytes:
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    now      = datetime.datetime.utcnow()
    expiry   = now + datetime.timedelta(days=CERT_DAYS)

    profile = {
        "AppIDName":                    bundle_id,
        "ApplicationIdentifierPrefix":  [team_id],
        "CreationDate":                 now,
        "ExpirationDate":               expiry,
        "IsXcodeManaged":               False,
        "Name":                         f"{bundle_id} Sideload Profile",
        "Platform":                     ["iOS", "iPadOS"],
        "TeamIdentifier":               [team_id],
        "TeamName":                     "RoostDev",
        "TimeToLive":                   CERT_DAYS,
        "UUID":                         str(uuid.uuid4()).upper(),
        "Version":                      1,
        "Entitlements": {
            "application-identifier":               f"{team_id}.{bundle_id}",
            "com.apple.developer.team-identifier":  team_id,
            "get-task-allow":                       True,
            "keychain-access-groups":               [f"{team_id}.*"],
        },
        "DeveloperCertificates": [cert_der],
        "ProvisionedDevices":    [],
    }
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def build_password_txt() -> bytes:
    return (
        f"Certificate Password\n"
        f"====================\n"
        f"Password : {PASSWORD}\n"
        f"\n"
        f"Use this password when importing the .p12 file\n"
        f"into your sideloading tool (AltStore, Sideloadly,\n"
        f"TrollStore, etc.).\n"
    ).encode()


def build_zip(p12_bytes: bytes, provision_bytes: bytes, bundle_id: str) -> bytes:
    buf  = io.BytesIO()
    safe = bundle_id.replace(".", "_")
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{safe}.p12",             p12_bytes)
        zf.writestr(f"{safe}.mobileprovision", provision_bytes)
        zf.writestr("password.txt",            build_password_txt())
    buf.seek(0)
    return buf.read()


# ── bot ───────────────────────────────────────────────────────────────────────
intents = discord.Intents.default()
bot     = commands.Bot(command_prefix="!", intents=intents)


@bot.event
async def on_ready():
    if GUILD_ID:
        await bot.tree.sync(guild=GUILD_ID)
    else:
        await bot.tree.sync()
    print(f"[roost] online as {bot.user}")


@bot.tree.command(
    name="buildcert",
    description="Generate P12 + provisioning profile for iOS/iPadOS sideloading"
)
@app_commands.describe(
    bundle_id="App bundle ID  e.g. com.example.myapp",
    team_id  ="10-char Apple Team ID  (fake OK for sideload tools)",
)
async def buildcert(
    interaction: discord.Interaction,
    bundle_id: str,
    team_id: str = "ROOST00001",
):
    await interaction.response.defer(thinking=True)

    try:
        ca_key,   ca_cert   = build_ca()
        leaf_key, leaf_cert = build_leaf(bundle_id, team_id, ca_key, ca_cert)

        p12_bytes       = build_p12(leaf_key, leaf_cert, ca_cert)
        provision_bytes = build_mobileprovision(bundle_id, team_id, leaf_cert)
        zip_bytes       = build_zip(p12_bytes, provision_bytes, bundle_id)

        safe = bundle_id.replace(".", "_")

        embed = discord.Embed(
            title       = "📦 Sideload Package Ready",
            description = f"`{bundle_id}`",
            color       = discord.Color.dark_gray(),
        )
        embed.add_field(name="P12 Password", value=f"`{PASSWORD}`",  inline=True)
        embed.add_field(name="Team ID",      value=f"`{team_id}`",   inline=True)
        embed.add_field(name="Valid For",    value=f"{CERT_DAYS}d",  inline=True)
        embed.add_field(
            name  = "Zip Contents",
            value = (
                f"`{safe}.p12`\n"
                f"`{safe}.mobileprovision`\n"
                f"`password.txt`"
            ),
            inline=False,
        )
        embed.set_footer(text="roost delivery")

        await interaction.followup.send(
            embed=embed,
            file=discord.File(io.BytesIO(zip_bytes), filename=f"{safe}_sideload.zip")
        )

    except Exception as exc:
        await interaction.followup.send(f"```\n[error] {exc}\n```")


if __name__ == "__main__":
    bot.run(BOT_TOKEN)
