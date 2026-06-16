import json
from channels.generic.websocket import AsyncWebsocketConsumer 

class LiveFeedConsumer(AsyncWebsocketConsumer):
    GROUP_NAME = "live_feed"    # The group name — all dashboard browsers join this same group

    async def connect(self):
        # A browser just opened the dashboard page.
        # Add it to the "live_feed" group so it receives updates.
        await self.channel_layer.group_add(self.GROUP_NAME,self.channel_name)
        await self.accept()
    
    async def disconnect(self, close_code):
        # The browser closed the tab.
        # Remove it from the group.
        await self.channel_layer.group_discard(self.GROUP_NAME,self.channel_name)

    async def new_activity(self,event):
        # A new log was saved! The signal sent us a message.
        # Forward the data to the browser as JSON text.
        await self.send(text_data=json.dumps(event["data"]))
        
         