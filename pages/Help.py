import streamlit as st
import streamlit.components.v1 as components

st.set_page_config(
    page_title="Help & BharatGPT Chatbot",
    page_icon="💬",
    layout="wide"
)

st.header("💬 Need Help? Chat with BharatGPT")
st.markdown("Interact with the BharatGPT AI agent for instant support and guidance.")

components.html(
    '''
    <iframe src="https://builder.corover.ai/params/?appid=b9a4faa1-abed-4eef-a28a-7caddb277e3a#/" 
        width="500px" height="600" style="border:none; border-radius:12px; overflow:hidden;">
    </iframe>
    '''
    ,
    height=620
)

st.markdown("---")
st.markdown("*Powered by BharatGPT AI Agent*")
