import logging, sys, json, hashlib
import discord
from discord.ext.commands import has_permissions
from enum import Enum
import requests

from .credentials import (
    HASH_SECRET,
    BOTOWNER_ALERT_CHANNEL,
    BOTOWNER_GUILD,
    BOTOWNER_MENTION,
    BOTOWNER_ALERT_ENABLED,
)
from .mail import send_verification_email

# Configure root logger
log = logging.getLogger()
log.setLevel(logging.INFO)

formatter = logging.Formatter(
    "%(asctime)s - %(name)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s"
)
sout = logging.StreamHandler(sys.stdout)
sout.setFormatter(formatter)
log.addHandler(sout)

# Switch to module logger
log = logging.getLogger(__name__)

intents = discord.Intents.default()
intents.members = True
intents.presences = True
bot = discord.Bot(
    "Contact @matticoli for assistance", intents=intents
)  # Create a bot object

user_roles = ["Student", "Alumni", "Faculty/Staff", "Prospective Student"]
noemail_roles = ["Prospective Student"]


class Config:
    verify_channels = {}
    verify_roles = {}
    mod_roles = {}


config = Config()

log.info("Loading config...")
try:
    with open("data/VerifyChannels.db", "r") as f:
        channels_json = json.loads("\n".join(f.readlines()))
        for i in channels_json:
            config.verify_channels[int(i)] = channels_json[i]
    log.info("Loaded channels db %s", str(config.verify_channels))
except Exception as e:
    log.error("Failed to load Channels DB: %s", e)
try:
    with open("data/VerifyRoles.db", "r") as f:
        roles_json = json.loads("\n".join(f.readlines()))
        for i in roles_json:
            config.verify_roles[int(i)] = roles_json[i]
    log.info("Loaded verified roles db %s", str(config.verify_roles))
except Exception as e:
    log.error("Failed to load verified roles DB: %s", e)
try:
    with open("data/ModRoles.db", "r") as f:
        mod_json = json.loads("\n".join(f.readlines()))
        for i in mod_json:
            config.mod_roles[int(i)] = mod_json[i]
    log.info("Loaded mod roles db %s", str(config.mod_roles))
except Exception as e:
    log.error("Failed to load mod roles DB: %s", e)


# Helpers
def generate_verification_code(email: str, user: str):
    return hashlib.md5(
        f"{email}{HASH_SECRET}{user}".encode(encoding="utf-8")
    ).hexdigest()[0:6]


def get_guild_role(guild: discord.Guild, role: int | str):
    try:
        return guild.get_role(int(role))
    except:
        try:
            return [r for r in guild.roles if r.name.lower() == role.lower()][0]
        except:
            log.error(
                "Failed to retrieve role %s in guild %s (%s)",
                role,
                guild.name,
                guild.id,
            )


def get_guild_channel(guild: discord.Guild, channel: int | str):
    try:
        return guild.get_channel(int(channel))
    except:
        try:
            return [c for c in guild.channels if c.name.lower() == channel.lower()][0]
        except:
            log.error(
                "Failed to retrieve channel %s in guild %s (%s)",
                channel,
                guild.name,
                guild.id,
            )
            return None


def check_is_wpi_employee(email: str):
    user = email.lower().split("@")[0]
    staff_req = requests.get(f"https://wpi.edu/people/staff/{user}")
    fac_req = requests.get(f"https://wpi.edu/people/faculty/{user}")
    return staff_req.status_code != 404 or fac_req.status_code != 404


async def alert_critical_error(*args, **kwargs):
    log.critical(*args, **kwargs)
    if BOTOWNER_ALERT_ENABLED:
        await get_guild_channel(BOTOWNER_GUILD, BOTOWNER_ALERT_CHANNEL).send(
            f"**<@{BOTOWNER_MENTION}> Critical error logged by trumbification:**\n"
            + str.format(*args),
            allowed_mentions=discord.AllowedMentions.all(),
        )


async def create_verification_thread(u: discord.Member) -> discord.Thread:
    channel = u.guild.system_channel
    try:
        try:
            channel = get_guild_channel(u.guild, config.verify_channels[u.guild.id])
        except Excepion as e:
            log.warn(
                "Failed to get configured channel for guild %s (%s). Defaulting to #landing\n\t%s",
                u.guild.name,
                u.guild.id,
                e,
            )
            channel = get_guild_channel(u.guild, "landing")
            if channel == None:
                raise Exception(
                    "No configured channel or #landing channel found in guild %s (%s)",
                    u.guild.name,
                    u.guild.id,
                )
    except Exception as e:
        alert_critical_error(
            "Error fetching channel named #landing in guild %s (%s): %s",
            u.guild.name,
            u.guild.id,
            e,
        )
        log.info(
            "Defaulting to system channel %s (%s) for guild %s (%s)",
            channel.name,
            channel.id,
            u.guild.name,
            u.guild.id,
        )
    thread_name = f"Verification - {u.name}"
    search_threads = [t for t in channel.threads if t.name == thread_name]
    log.info(
        "Existing verification threads for user %s in guild %s: %s",
        u.name,
        u.guild.name,
        search_threads,
    )
    thrd = (
        search_threads[0]
        if len(search_threads) > 0
        else await channel.create_thread(name=thread_name, auto_archive_duration=60)
    )
    view = RoleSelectView(thread=thrd, timeout=None)
    log.info("Registered persistent view: %s %s", view.id, view.is_persistent())
    await thrd.send(
        f"Welcome <@{u.id}>! Let's get you set up so you can access the rest of this server. This will only take a minute.\n\nIf you have questions or need assistance, you can @ a moderator/admin in this thread for help. You can change roles later by running `/verify`",
        view=view,
        allowed_mentions=discord.AllowedMentions.all(),
    )
    return thrd


async def assign_roles(interaction: discord.Interaction, role: str, email: str = "N/A"):
    usr = interaction.user
    gld = interaction.guild
    guild_roles = config.verify_roles[gld.id] if gld.id in config.verify_roles else {}
    try:
        rm_roles = [r for r in usr.roles if r.id in guild_roles.values() or r.name in user_roles]
        log.info(
            "Attempting to remove roles %s for %s (%s) in %s (%s)",
            str(rm_roles),
            usr.name,
            usr.id,
            gld.name,
            gld.id,
        )
        await usr.remove_roles(*rm_roles, reason="trumbification (Remove old roles)")
        log.info(
            "Successfully removed roles %s for %s (%s) in %s (%s)",
            str(rm_roles),
            usr.name,
            usr.id,
            gld.name,
            gld.id,
        )
        assign_role = (
            get_guild_role(gld, int(guild_roles[role]))
            if role in guild_roles
            else get_guild_role(gld, role)
        )
        log.info(
            "Got %s as %s role in %s (%s)",
            assign_role,
            role,
            gld.name,
            gld.id,
        )
        await usr.add_roles(assign_role, reason="trumbification")
        log.info(
            "Successfully assigned %s to %s (%s) %s (%s)",
            assign_role,
            usr.name,
            usr.id,
            gld.name,
            gld.id,
        )
        await interaction.followup.send(
            f"Verification success, welcome! You should be able to see the rest of the server now. Feel free to reach out to a moderator/admin with any questions or issues."
        )
        log.info(
            "Successfully verified user %s (%s) as %s in %s (%s)",
            usr.name,
            usr.id,
            role,
            gld.name,
            gld.id,
        )
    except Exception as e:
        await alert_critical_error(
            "Failed to retrieve and assign %s role for %s (%s) in %s (%s): %s",
            role,
            usr.name,
            usr.id,
            gld.name,
            gld.id,
            e,
        )
        try:
            await interaction.followup.send(
                "Verification was successful, but I was unable to update your roles. Please try again with `/verify` or reach out to an admin/mod for assistance"
            )
        except Exception as e:
            await alert_critical_error("Failed to notify user of failure: %s", e)


# Event Handlers
@bot.event
async def on_ready():
    log.info("Ready")
    bot.add_view(RoleSelectView(timeout=None))
    bot.add_view(CodePromptView("null@example.com", "Guest", showHelp=True, timeout=None))
    await bot.change_presence(
        status=discord.Status.online,
        activity=discord.Game("Contact @matticoli for assistance"),
    )
    if BOTOWNER_ALERT_ENABLED:
        await alert_critical_error("trumbification restarted unexpectedly")


@bot.event
async def on_member_join(u: discord.Member):
    log.info("User %s (id %s) joined server %s", u.name, u.id, u.guild.name)
    await create_verification_thread(u)


# UI
class RoleSelectView(discord.ui.View):
    """
    Initial message with role selection
    """

    def __init__(self, thread: discord.Thread = None, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        for r in user_roles:
            btn = discord.ui.Button(
                label=r, style=discord.ButtonStyle.blurple, custom_id=r
            )

            def btn_cb(r):
                return lambda interaction: self.on_select(r, interaction)

            btn.callback = btn_cb(r)
            self.add_item(btn)
        if thread != None and thread.guild.id in config.mod_roles:
            mod_mention = thread.guild.get_role(config.mod_roles[thread.guild.id]).id
            btn = discord.ui.Button(
                label="Request Assistance",
                style=discord.ButtonStyle.success,
                custom_id="help_button",
            )
            btn.callback = lambda interaction: interaction.response.send_message(
                f"Hey <@&{mod_mention}>, can someone help out here when you have a moment?",
                allowed_mentions=discord.AllowedMentions.all(),
            )
            self.add_item(btn)
        elif thread == None:
            # Reinitializing persistent button, assume thread was originally passed
            btn = discord.ui.Button(
                label="Request Assistance",
                style=discord.ButtonStyle.success,
                custom_id="help_button",
            )
            btn.callback = lambda interaction: interaction.response.send_message(
                f"Hey <@&{interaction.guild.get_role(config.mod_roles[interaction.guild.id]).id}>, can someone help out here when you have a moment?",
                allowed_mentions=discord.AllowedMentions.all(),
            )
            self.add_item(btn)
        else:
            log.warn(
                "No mod role configured, excluding help button in guild %s (%s)",
                thread.guild.name,
                thread.guild.id,
            )

    async def on_select(self, role: str, interaction: discord.Interaction):
        log.info(
            f"User %s (%s) selected %s in %s (%s)",
            interaction.user.name,
            interaction.user.id,
            role,
            interaction.guild.name,
            interaction.guild.id,
        )

        async def modal_callback():
            self.clear_items()
            await interaction.edit_original_response(view=self)

        if role in noemail_roles:
            await interaction.response.defer()
            await assign_roles(interaction, role)
            await modal_callback()
            return

        modal = MailModal(role, modal_callback, title=f"{role} Verification")
        await interaction.response.send_modal(modal)


class MailModal(discord.ui.Modal):
    """
    Email address prompt modal
    """

    def __init__(self, role: str, view_callback, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.add_item(
            discord.ui.InputText(
                label="Please enter your WPI email address",
                min_length=10,
                placeholder="trumbus@wpi.edu",
            )
        )
        self.role = role
        self.view_callback = view_callback

    async def callback(self, interaction: discord.Interaction):
        await interaction.response.defer(ephemeral=True, invisible=False)
        email = self.children[0].value.lower()
        is_valid = (
            email.endswith("@wpi.edu")
            or email.endswith("@alum.wpi.edu")
            or email.endswith("@massdigi.org")
        )
        is_user = not ("-" in email or "_" in email)
        if is_valid and is_user:
            is_employee = check_is_wpi_employee(email)
            if is_employee and self.role != "Faculty/Staff":
                await alert_critical_error(
                    "User %s (%s) attempted to verify as %s with faculty email (%s) in %s (%s)",
                    interaction.user.name,
                    interaction.user.id,
                    self.role,
                    email,
                    interaction.guild.name,
                    interaction.guild.id,
                )
                await interaction.followup.send(
                    f"The email you entered appears in the faculty/staff directory, so I am unable to verify you with {self.role} roles. If you believe this is an error, please reach out to <@{BOTOWNER_MENTION}>, or contact a moderator in this server for manual verification.",
                    allowed_mentions=discord.AllowedMentions.all(),
                )
            elif (not is_employee) and (self.role == "Faculty/Staff"):
                await alert_critical_error(
                    "User %s (%s) attempted to verify as Faculty/Staff with non-faculty email (%s) in %s (%s)",
                    interaction.user.name,
                    interaction.user.id,
                    email,
                    interaction.guild.name,
                    interaction.guild.id,
                )
                await interaction.followup.send(
                    f"I was unable to find that email address in the faculty/staff directory. If you believe this is an error, please reach out to <@{BOTOWNER_MENTION}>, or contact a moderator in this server for manual verification.",
                    allowed_mentions=discord.AllowedMentions.all(),
                )
            else:
                log.info(
                    "Verified user %s (%s) email, Faculty/Staff=%s. Sending verification code.",
                    interaction.user.name,
                    interaction.user.id,
                    is_employee,
                )
                send_verification_email(
                    email, generate_verification_code(email, str(interaction.user.id))
                )
                await interaction.followup.send(
                    "Check your email for a verification code. It may have mistakenly wound up in your junk folder. When you're ready, click the button below.",
                    view=CodePromptView(email, self.role),
                )
                await self.view_callback()
        else:
            await interaction.followup.send(
                "That is not a valid WPI email address. Please try again, or reach out to a admin/mod if you're having issues."
            )


class CodePromptView(discord.ui.View):
    """
    Enter code view
    """

    def __init__(self, email: str, role: str, showHelp: bool = False, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.email = email
        self.role = role
        if showHelp:
            btn = discord.ui.Button(
                label="Request Assistance",
                style=discord.ButtonStyle.success,
                custom_id="help_button",
            )
            btn.callback = lambda interaction: interaction.response.send_message(
                f"Hey <@&{config.mod_roles[interaction.guild.id]}>, can someone help out here when you have a moment?",
                allowed_mentions=discord.AllowedMentions.all(),
            )
            self.add_item(btn)


    @discord.ui.button(
        label="Enter Code", style=discord.ButtonStyle.blurple, custom_id="code_button"
    )
    async def button_callback(self, button, interaction: discord.Interaction):
        if self.email == "null@example.com":
            await interaction.response.send_message("This verification code has expired. Please run `/verify` to try again", ephemeral=True)
            return
        modal = CodeModal(
            self.email, self.role, title=f"Email Verification ({self.email})"
        )
        await interaction.response.send_modal(modal)
        await modal.wait()
        await interaction.delete_original_response()


class CodeModal(discord.ui.Modal):
    """
    Code view
    """

    def __init__(self, email: str, role: str, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self.add_item(
            discord.ui.InputText(
                label="Verification Code", max_length=10, placeholder="b3aNs"
            )
        )
        self.email = email
        self.role = role

    async def callback(self, interaction: discord.Interaction):
        code = self.children[0].value
        if code == generate_verification_code(self.email, interaction.user.id):
            await interaction.response.defer(ephemeral=False)
            await assign_roles(interaction, self.role, self.email)
        else:
            await interaction.response.send_message(
                "That code does not match. Please try again or contact an admin for assistance",
                ephemeral=True,
                view=CodePromptView(self.email, self.role, showHelp=interaction.guild.id in config.mod_roles)
            )


# Slash Commands
@bot.slash_command(
    name="verify",
    description="Manually restart verification to change roles (e.g. if you've recently enrolled or graduated)",
)
async def verify(ctx: discord.ApplicationContext):
    log.info(
        "User %s (%s) would like to reverify in guild %s (%s)",
        ctx.author.name,
        ctx.author.id,
        ctx.guild,
        ctx.guild.id,
    )
    # await ctx.interaction.response.defer(ephemeral=True, invisible=True)
    thrd = await create_verification_thread(ctx.author)
    if ctx.channel_id != thrd.id:
        await ctx.interaction.response.send_message(
            f"Open <#{thrd.id}> thread to continue",
            ephemeral=True,
            allowed_mentions=discord.AllowedMentions.all(),
        )
    else:
        await ctx.interaction.response.send_message(
            "Restarting verification", ephemeral=True
        )


@bot.slash_command(
    name="set_verification_channel",
    description="[ADMIN ONLY] Set the channel that verification messages/threads will be sent in",
    guild_only=True,
    default_member_permissions=discord.Permissions(administrator=True),
)
@has_permissions(administrator=True)
async def set_verification_channel(
    ctx: discord.ApplicationContext, channel: discord.TextChannel
):
    log.info(
        "User %s (%s) setting verification channel to #%s (%s) in %s (%s)",
        ctx.author.name,
        ctx.author.id,
        channel.name,
        channel.id,
        channel.guild.name,
        channel.guild.id,
    )
    # Silly reassignment stuff to mutate
    config.verify_channels[ctx.guild.id] = channel.id
    log.debug(config.verify_channels)
    try:
        with open("data/VerifyChannels.db", "w") as f:
            f.write(json.dumps(config.verify_channels))
    except Exception as e:
        alert_critical_error(f"Failed to save configuration db: %s", e)
    await ctx.respond(f"Set verification channel to `#{channel}`", ephemeral=True)


@bot.slash_command(
    name="set_moderator_role",
    description="[ADMIN ONLY] Set role to ping for manual verification/help",
    guild_only=True,
    default_member_permissions=discord.Permissions(administrator=True),
)
@has_permissions(administrator=True)
async def set_moderator_role(
    ctx: discord.ApplicationContext,
    role: discord.Role,
):
    log.info(
        "User %s (%s) setting admin role for %s to %s (%s) in %s (%s)",
        ctx.author.name,
        ctx.author.id,
        role,
        role.name,
        role.id,
        ctx.guild.name,
        ctx.guild.id,
    )
    config.mod_roles[ctx.guild.id] = role.id
    log.debug(config.mod_roles)
    try:
        with open("data/ModRoles.db", "w") as f:
            f.write(json.dumps(config.mod_roles))
        log.info("Mod roles db saved successfully")
    except Exception as e:
        alert_critical_error(f"Failed to save mod roles db: %s", e)
    await ctx.respond(f"Set mod role to `@{role.name}`", ephemeral=True)


@bot.slash_command(
    name="set_verified_role",
    description="[ADMIN ONLY] Set server role assigned for given verification type",
    guild_only=True,
    default_member_permissions=discord.Permissions(administrator=True),
)
@has_permissions(administrator=True)
async def set_verified_role(
    ctx: discord.ApplicationContext,
    role: discord.Option(choices=user_roles),
    guild_role: discord.Role,
):
    log.info(
        "User %s (%s) setting verification role for %s to %s (%s) in %s (%s)",
        ctx.author.name,
        ctx.author.id,
        role,
        guild_role.name,
        guild_role.id,
        ctx.guild.name,
        ctx.guild.id,
    )
    if ctx.guild.id not in config.verify_roles:
        config.verify_roles[ctx.guild.id] = {}
    config.verify_roles[ctx.guild.id][role] = guild_role.id
    log.debug(config.verify_roles)
    try:
        with open("data/VerifyRoles.db", "w") as f:
            f.write(json.dumps(config.verify_roles))
    except Exception as e:
        alert_critical_error(f"Failed to save configuration db: %s", e)
    await ctx.respond(
        f"Set verification role for {role} to `@{guild_role}`", ephemeral=True
    )


@bot.slash_command(
    name="view_verified_config",
    description="[ADMIN ONLY] View configured channels/roles for verification",
    guild_only=True,
    default_member_permissions=discord.Permissions(administrator=True),
)
@has_permissions(administrator=True)
async def view_verified_config(ctx: discord.ApplicationContext):
    log.info(
        "User %s (%s) requesting to view verification config in %s (%s)",
        ctx.author.name,
        ctx.author.id,
        ctx.guild.name,
        ctx.guild.id,
    )
    chan = "default"
    mod = "none"
    roles = "default"
    guild = ctx.guild.id
    if guild in config.verify_channels:
        chan = f"`#{get_guild_channel(ctx.guild, config.verify_channels[guild])}`"
    if guild in config.mod_roles:
        mod = f"`@{get_guild_role(ctx.guild, config.mod_roles[ctx.guild.id])}`"
    if guild in config.verify_roles:
        guild_roles = config.verify_roles[guild]
        roles = "\n".join(
            [
                f"{r}: `@{get_guild_role(ctx.guild, guild_roles[r])}`"
                if r in guild_roles
                else f"{r}: `@{get_guild_role(ctx.guild, r)}`"
                for r in user_roles
            ]
        )

@bot.slash_command(
    name="audit_unverified_members",
    description="[ADMIN ONLY] List members without a verified role",
    guild_only=True,
    default_member_permissions=discord.Permissions(administrator=True),
)
@has_permissions(administrator=True)
async def audit_unverified_members(ctx: discord.ApplicationContext, post_in_channel: bool = False):
    log.info(
        "User %s (%s) requesting to audit unverified members %s (%s)",
        ctx.author.name,
        ctx.author.id,
        ctx.guild.name,
        ctx.guild.id,
    )
    unverified_users = []
    verified_users = []
    configured_roles = config.verify_roles[ctx.guild.id].values() if ctx.guild.id in config.verify_roles else []
    for u in ctx.guild.members:
        if not u.bot:
            verified = False
            for r in u.roles:
                if r.id in configured_roles or r.name in user_roles:
                    verified = True
                    break
            if verified:
                verified_users.append(u.id)
            else:
                uroles = ", ".join([f"`{r.name}`" for r in u.roles[1:]])
                unverified_users.append(f"<@{u.id}>\n\t{uroles}")
    report = "\n".join(unverified_users)
    await ctx.respond(f"Found {len(unverified_users)} verified and {len(verified_users)} unverified users\n\n**Unverified Users**:\n{report}", ephemeral=not post_in_channel)
