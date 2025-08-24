import uvicorn
import yfinance as yf
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

mcp = FastMCP("Stocks")


@mcp.tool()
def get_current_stock_price(ticker):
    """Get Current Stock Price for a given Ticker Symbol"""
    return {"currency": "USD", "value": yf.Ticker(ticker).info["open"]}


@mcp.tool()
def get_historical_stock_splits(ticker):
    """Get list of historical stock splits"""
    history = []
    for timestamp, ratio in yf.Ticker(ticker).splits.to_dict().items():
        history.append(
            {
                "date": timestamp.strftime("%A, %B %d, %Y") + f", {timestamp.tzname()}",
                "ratio": ratio,
            }
        )
    return {"total": len(history), "history": history}


app = Starlette(
    routes=[
        Mount("/", app=mcp.sse_app()),
    ]
)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
