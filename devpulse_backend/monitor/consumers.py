import json
from channels.generic.websocket import AsyncWebsocketConsumer 

class LiveFeedConsumer(AsyncWebsocketConsumer):
    GROUP_NAME = "live_feed"

    async def connect(self):
        await self.channel_layer.group_add(self.GROUP_NAME,self.channel_name)
        await self.accept()
    
    async def disconnect(self, close_code):
        await self.channel_layer.group_discard(self.GROUP_NAME,self.channel_name)

    async def new_activity(self,event):
        await self.send(text_data=json.dumps(event["data"]))
        
         