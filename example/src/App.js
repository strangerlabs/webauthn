
/**
 * Dependencies
 * @ignore
 */
import React, { useState } from 'react'
import { Container, Row, Col, Form, Button } from 'react-bootstrap'
import Client from 'webauthn/client'

/**
 * Module Dependencies
 * @ignore
 */

/**
 * App
 * @ignore
 */
function App () {
  const [name, setName] = useState('')
  const [username, setUsername] = useState('')
  const [webauthn] = useState(new Client())

  function onRegister () {
    webauthn.register({ name, username })
  }

  function onLogin () {
    webauthn.login({ username })
  }

  function onLogout () {
    webauthn.logout()
  }

  return (
    <Container>
      <Row style={{ paddingTop: 80 }}>
        <Col>
          <h3>Register</h3>
          <Form>
            <Form.Group>
              <Form.Label>Username</Form.Label>
              <Form.Control
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
              ></Form.Control>
            </Form.Group>
            <Form.Group>
              <Form.Label>Name</Form.Label>
              <Form.Control
                type="text"
                value={name}
                onChange={e => setName(e.target.value)}
              ></Form.Control>
              <Form.Text className="text-muted">This name will be displayed publicly.</Form.Text>
            </Form.Group>
            <Button variant="primary" onClick={onRegister}>
              Register
            </Button>
          </Form>
        </Col>
        <Col>
          <h3>Login</h3>
          <Form>
            <Form.Group>
              <Form.Label>Username</Form.Label>
              <Form.Control type="text" value={username} onChange={e => setUsername(e.target.value)}></Form.Control>
            </Form.Group>
            <Button variant="primary" onClick={onLogin}>
              Login
            </Button>
          </Form>
        </Col>
      </Row>
      <Row style={{ paddingTop: 80 }}>
        <Col>
          <Button variant="outline-primary" block onClick={onLogout}>
            Logout
          </Button>
        </Col>
      </Row>
    </Container>
  )
}

/**
 * Exports
 * @ignore
 */
export default App;
