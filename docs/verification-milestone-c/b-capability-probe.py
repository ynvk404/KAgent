import asyncio, json, re
from tests.ui.test_light_theme_app import make_app, RecordingDriver
async def main():
 app=make_app("light")
 app.driver_class=RecordingDriver
 async with app.run_test(headless=False, size=(100,38)) as pilot:
  await pilot.pause()
  paints=[chunk for chunk in app._driver.output if re.search(r"48;(?:2|5);",chunk)]
  result=json.dumps(dict(color_system=app.console.color_system, first_backgrounds=re.findall(r"48;(?:2;[0-9;]+|5;[0-9]+)", paints[0])[:12]))
 print(result)
asyncio.run(main())
