import json
from channels.generic.websocket import AsyncWebsocketConsumer 

class LiveFeedConsumer(AsyncWebsocketConsumer):
    GROUP_NAME = "live_feed"    # The group name — all dashboard browsers join this same group
    
    # A browser just opened the dashboard page.
    async def connect(self):
        # 1. Access the user profile attached to this connection by our middleware
        await self.channel_layer.group_add(self.GROUP_NAME, self.channel_name)
        await self.accept()
    
    # The browser closed the tab.
    async def disconnect(self, close_code):
        # Remove it from the group.
        await self.channel_layer.group_discard(self.GROUP_NAME,self.channel_name)

    # A new log was saved! The signal sent us a message.
    async def new_activity(self,event):
        # Forward the data to the browser as JSON text.
        await self.send(text_data=json.dumps(event["data"]))
        
         