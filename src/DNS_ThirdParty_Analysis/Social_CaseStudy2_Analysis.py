import pandas as pd

df = pd.read_csv('src/Source_Data/DNS_Identifier_Results_10k_domains.csv', sep=',')

# Use a set to automatically dedupe, then convert to list
social_media_domains = list({
    'facebook.com', 'fbsbx.com', 'facebook-hardware.com',
    'instagram.com', 'whatsapp.com', 'whatsapp.net', 'threads.net',
    'twitter.com', 'x.com', 'tiktok.com', 'tiktokv.com', 'tiktokshop.com',
    'snapchat.com', 'pinterest.com', 'linkedin.com', 'reddit.com', 'redditmedia.com',
    'redditstatic.com', 'discord.com', 'discord.media', 'discordapp.com',
    'telegram.org', 'telegram.me', 't.me', 'wechat.com', 'weixin.com',
    'weibo.com', 'weibocdn.com', 'vk.com', 'tumblr.com', 'mastodon.social',
    'bsky.app', 'bsky.social', 'bsky.network', 'myspace.com', 'quora.com', 'meetup.com', 'nextdoor.com', 'twitch.tv',
    'line.me', 'kakao.com', 'viber.com', 'signal.org',
    'truthsocial.com', 'douyin.com', 'douyincdn.com', 'xiaohongshu.com', 'ok.ru', 'flickr.com', 'foursquare.com'
})

print(f"Number of target domains in list: {len(social_media_domains)}")

# ✅ Exact match instead of substring match
filtered = df[df['DOMAIN'].str.lower().isin(social_media_domains)]

# Deduplicate on DOMAIN
unique_social_media_domains = filtered.drop_duplicates(subset=['DOMAIN'])

print(f"Unique Social Media domains found: {len(unique_social_media_domains)}")

# Show which ones from your list are MISSING from the CSV (helpful for debugging)
found = set(unique_social_media_domains['DOMAIN'].str.lower())
missing = set(social_media_domains) - found
print(f"Domains in your list but NOT in the CSV ({len(missing)}):")
for d in sorted(missing):
    print(f"  - {d}")

unique_social_media_domains.to_csv('src/Source_Data/Social_Media_Domains_Analysis.csv', index=False)

df2 = pd.read_csv('src/Source_Data/Social_Media_Domains_Analysis.csv', sep=',')
dependencies = df2['TYPE'].value_counts()
print(f"Dependency types:\n{dependencies}")