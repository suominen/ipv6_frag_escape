SITE := site
DEST := haig:/ipv6_frag_escape/
SSH_IDENTITY := $(HOME)/.ssh/id-kimmo-cloud-htdocs

BANNER_SVG := $(SITE)/assets/ipv6-frag-escape-tracker.svg
BANNER_PNG := $(SITE)/static/ipv6-frag-escape-tracker.png

.PHONY: build dist banner

# Rasterise the social-media / OpenGraph banner from its SVG source.
# The PNG is committed, so this — and the resvg + Roboto-fonts
# dependency — is only needed after editing the SVG.
banner:
	resvg $(BANNER_SVG) $(BANNER_PNG)

build:
	cd $(SITE) && hugo --minify --gc --cleanDestinationDir

dist: build
	rsync -avz --delete --chmod=Da+rx,Fa+r -e 'ssh -i $(SSH_IDENTITY) -o IdentitiesOnly=yes' $(SITE)/public/ $(DEST)
