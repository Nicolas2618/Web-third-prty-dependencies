import pandas as pd

df = pd.read_csv('src/Source_Data/cdn_results/cdn_results_10000_cleaned.csv', sep=',')

ai_domains = ['anthropic.com', 'chatgpt.com', 'claude.ai', 'openai.com', 'claude.com', 'character.ai', 'mistral.ai',
              'perplexity.ai', 'x.ai', 'qwen.ai', 'otter.ai', 'suno.ai', 'krisp.ai', 'jetbrains.ai', 'lmstudio.ai', 'vllm.ai'
              'openrouter.ai', 'opencode.ai', 'trae.ai', 'sider.ai', 'read.ai', 'scite.ai', 'forethought.ai', 'higgsfield.ai',
              'pixverse.ai', 'seaart.ai', 'shedevrun.ai', 'granola.ai', 'lovart.ai', 'wisprflow.ai', 'cortana.ai', 'polybuzz.ai',
               'poly-ai.chat', 'polyspeak.ai', 'talkie-ai.com', 'onlymonster.ai', 'crushon.ai', 'sardine.ai', 'verisoul.ai', 'trafficguard.ai',
               'nrich.ai', 'factors.ai', 'axon.ai', 'dimensions.ai', 'vivint.ai', 'rise-ai.com', 'shortpixel.ai', 'secureprivacy.ai',
               'mikmak.ai', 'anota.ai', 'gmgn.ai', 'superops.ai', 'securiti.ai', 'vdo.ai', 'dera.ai', 'shoplift.ai', 'smartico.ai',
               'datahive.ai', 'drift-pixel.ai', 'programmaticx.ai', 'syntx.ai', 'toolify.ai',] 

pattern = '|'.join(ai_domains)

# ✅ Fixed: no .nunique() inside the filter
ai_domains = df[df['website'].str.contains(pattern, case=False, na=False)]

# ⭐ Keep only unique domains (removes 879 duplicate rows)
unique_ai_domains = ai_domains.drop_duplicates(subset=['website'])

print(f"Unique AI-related domains: {len(unique_ai_domains)}")

unique_ai_domains.to_csv('src/Source_Data/AI_Domains_Analysis.csv', index=False)


df2 = pd.read_csv('src/Source_Data/AI_Domains_Analysis.csv', sep=',')

dependencies = df2['cdn_types'].value_counts()
#providers = df2['PROVIDER'].value_counts()
#print(f'{providers}')
print (f"Dependency types:\n{dependencies}")