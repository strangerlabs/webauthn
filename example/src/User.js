import React from 'react'
import { Container, Row, Col, Button, CardColumns } from 'react-bootstrap'
import CredentialCard from './CredentialCard'
import Client from 'webauthn/client'
import 'bootstrap/dist/css/bootstrap.min.css'

class User extends React.Component {
  constructor (props) {
    super(props)

    this.state = {
      credentials: []
    }

    fetch('credentials', {
      method: 'GET',
      credentials: 'include',
    }).then(response => {
      if (response.status !== 200) {
        console.error(response.message)
        return
      }
      return response.json()
    }).then(credentials => {
      this.setState({ credentials })
    })
  }

  logout = () => {
    (new Client()).logout().then(() => this.props.onLogout())
  }

  render () {
    return (
      <Container>
        <Row style={{ paddingTop: 80}}>
          <Col>
            <h2>Welcome {this.props.user.username}</h2>
            <h3>Your credentials:</h3>
          </Col>
          <Col className="text-right">
            <Button variant="primary" onClick={this.logout}>Log Out</Button>
          </Col>
        </Row>
        <CardColumns>
          {this.state.credentials.map(credential =>
            <Col key={credential.credID}><CredentialCard credential={credential} /></Col>
          )}
        </CardColumns>
      </Container>
    )
  }
}

export default User;
