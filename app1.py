from dash import Dash, html, dcc, callback, Input, Output
import plotly.express as px
import pandas as pd
import dash_bootstrap_components as dbc

from dash import Dash, html, dcc
import plotly.express as px
import pandas as pd
import dash_bootstrap_components as dbc

# Load data frames
df = pd.read_csv("<csv file>")
df1 = pd.read_csv("<csv file>")
df2 = pd.read_csv("<csv file>")
df3 = pd.read_csv("<csv file>")

# Metric 1: Emails Delivered vs Identified Phishing Emails Delivered
count_delivered = df[df['last_reply'] == '250 OK'].shape[0]
identified_phishing = df[df['from'] == 'evil@evil-org.com'].shape[0]

data1 = {
    "Category": ["Delivered Total", "Identified Phishing Delivered"],
    "Count": [count_delivered, identified_phishing]
}

fig1 = px.pie(
    data1,
    values='Count',
    names='Category',
    title='Emails Delivered vs Identified Phishing Emails Delivered',
    color_discrete_map={'Delivered Total': 'green', 'Identified Phishing Delivered': 'red'},
    template='plotly'  # Apply dark theme
)

# Metric 2: Emails with URLs vs Clicked on URLs
has_urls = df1[df1['id.resp_p'] == 25].shape[0]
clicked_urls = df2[df2['from'] == 'evil@evil-org.com'].shape[0]

data2 = {
    "Category": ["Email Has URLs", "Clicked on URLs"],
    "Count": [has_urls, clicked_urls]
}

fig2 = px.pie(
    data2,
    values='Count',
    names='Category',
    title='Emails with URLs vs Clicked on URLs',
    template='plotly'  # Apply dark theme
)

# Metric 3: Emails Delivered vs Replied to Email
replied_emails = df[df['mailfrom'] == 'victim@clever-nova.com'].shape[0]

data3 = {
    "Category": ["Delivered Total", "Replied to Email"],
    "Count": [count_delivered, replied_emails]
}

fig3 = px.pie(
    data3,
    values='Count',
    names='Category',
    title='Emails Delivered vs Replied to Email',
    template='plotly'  # Apply dark theme
)

# Metric 4: Clicked on URLs vs Submitted Credentials
submitted_credentials = df3[(df3['method'] == 'POST') & (df3['request_body_len'] > 10)].shape[0]

data4 = {
    "Category": ["Clicked on URLs", "Submitted Credentials"],
    "Count": [clicked_urls, submitted_credentials]
}

fig4 = px.pie(
    data4,
    values='Count',
    names='Category',
    title='Clicked on URLs vs Submitted Credentials',
    template='plotly'  # Apply dark theme
)
# Trend Analysis
# Metric 5: Tracking the number of phishing emails replicated over time

df['date'] = df['ts'].apply(lambda x: pd.Timestamp(x, unit='s').date())
replies_df = df[df['mailfrom'] == 'victim@clever-nova.com']
daily_replies = replies_df.groupby('date').size().reset_index(name='Count')

# Plot the line chart
fig5 = px.line(
    daily_replies,
    x='date',
    y='Count',
    title='Number of Phishing Emails Replied to Over Time',
    labels={'date': 'Date', 'Count': 'Number of Replies'},
    template='plotly'  # Apply dark theme
)

# Metric 6: Tracking the number of clicked URLs over time against phishing emails

# Convert 'ts' to datetime and extract date
df2['date'] = df2['ts'].apply(lambda x: pd.Timestamp(x, unit='s').date())

# Create a DataFrame for clicked URLs count by date
clicked_urls_per_date = df2['date'].value_counts().reset_index()
clicked_urls_per_date.columns = ['date', 'Count']
clicked_urls_per_date = clicked_urls_per_date.sort_values('date')  # Sort by date

# Create the line chart using Plotly
fig6 = px.line(
    clicked_urls_per_date, 
    x='date',  # Ensure this matches the 'date' column
    y='Count',
    title='Number of Clicked URLs Over Time Against Phishing Emails',
    labels={'date': 'Date', 'Count': 'Number of Clicked Phishing URLs'},
    template='plotly'  # Apply dark theme
)

# Initialize the Dash app with the DARKLY theme
external_stylesheets = [dbc.themes.CERULEAN]
app = Dash(__name__, external_stylesheets=external_stylesheets)

# App layout
app.layout = dbc.Container([
    dbc.Row(html.H1("Phishing Metrics Against Organizational Data", className="text-center text-primary")),
    dbc.Row(html.H4("Prepared by Cory Keller", className="text-center text-info")),
    
    dbc.Row([
        dbc.Col(dcc.Graph(figure=fig1, id='pie-chart-1', style={'height': 600}), width=6),
        dbc.Col(dcc.Graph(figure=fig2, id='pie-chart-2', style={'height': 600}), width=6),
    ], className="mb-4"),
    
    dbc.Row([
        dbc.Col(dcc.Graph(figure=fig3, id='pie-chart-3', style={'height': 600}), width=6),
        dbc.Col(dcc.Graph(figure=fig4, id='pie-chart-4', style={'height': 600}), width=6),
    ], className="mb-4"),
    
    dbc.Row([
        dbc.Col(dcc.Graph(figure=fig5, id='line-chart-1', style={'height': 600}), width=6),
        dbc.Col(dcc.Graph(figure=fig6, id='line-chart-2', style={'height': 600}), width=6),
    ]),
    
], fluid=True)

# Run the app
if __name__ == '__main__':
    app.run(debug=False, host='192.168.1.100', port=80)