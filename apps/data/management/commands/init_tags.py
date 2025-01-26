from django.core.management.base import BaseCommand
from apps.data.models import Tag

class Command(BaseCommand):
    help = 'Initialize default tags'

    def handle(self, *args, **kwargs):
        self.stdout.write('Creating default tags...')
        Tag.init_tags()
        self.stdout.write(self.style.SUCCESS('Successfully created default tags')) 