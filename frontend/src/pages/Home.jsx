import './Home.css'

function Home() {
  const team = [
    { name: 'Jeffrey Risberg', role: 'Team Member' },
    { name: 'Krishna Rajaraman', role: 'Team Member' },
    { name: 'Surya Anand', role: 'Team Member' },
  ]

  return (
    <div className="home page">
      <h1>Hackathon Team</h1>
      <p>Welcome to our hackathon project! Here's our team:</p>
      <ul className="team-list">
        {team.map((member) => (
          <li key={member.name}>
            <strong>{member.name}</strong> — {member.role}
          </li>
        ))}
      </ul>
    </div>
  )
}

export default Home
