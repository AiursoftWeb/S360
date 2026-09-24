using Aiursoft.CommandFramework;
using Aiursoft.S360.Client;

return await new NestedCommandApp().WithFeature(new CheckHandler()).RunAsync(args);
